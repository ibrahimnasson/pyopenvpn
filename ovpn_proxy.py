#!/bin/python3
import random
import logging
import socket
import io
import ipaddress
import threading
import select
import time
import queue
from argparse import ArgumentParser
from datetime import datetime, timedelta
from scapy.all import *

from pyopenvpn import Client, Settings


class SOCKS5Connection(threading.Thread):
    def __init__(self, server, sock, src_port, dest_host, dest_port):
        super().__init__()
        self.daemon = True
        self.server = server
        self.sock = sock
        self.src_port = src_port
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.running = True
        self.log = server.log
        self.outgoing_packets = []

        self.tunnel_in_queue = queue.Queue()

    def run(self):
        # FIXME: I HAVE NO IDEA HOW TCP WORKS, the last ACK is fucked up, the
        # whole thing is slow, breaks down on large pages and may explode at
        # any time.

        # SYN
        syn = TCP(sport=self.src_port, dport=self.dest_port, seq=random.randint(0, 0xfffffff))
        self.outgoing_packets.append(syn)

        # Wait for SYN ACK
        synack = self.tunnel_in_queue.get()
        # FIXME: check if it's actually a SYN ACK

        # ACK the SYN ACK
        hsack = TCP(sport=self.src_port, dport=self.dest_port, flags='A',
                    seq=synack.ack, ack=synack.seq + 1)
        self.outgoing_packets.append(hsack)

        l_seq = hsack.seq
        r_seq = hsack.ack

        self.log.info("Opened connection to %s:%d", self.dest_host, self.dest_port)

        self.sock.settimeout(0.001)
        while self.running:
            try:
                data = self.sock.recv(2048)
                if not data:
                    break
            except (socket.timeout, BrokenPipeError):
                data = None

            if data:
                packet = TCP(sport=self.src_port, dport=self.dest_port, flags='A',
                             seq=l_seq, ack=r_seq)
                packet /= Raw(load=data)
                self.outgoing_packets.append(packet)
                l_seq += len(data)

            try:
                packet = self.tunnel_in_queue.get(block=False)
                self.sock.send(bytes(packet.payload))
                assert packet.ack == l_seq
                r_seq = packet.seq
            except queue.Empty:
                pass
            except BrokenPipeError:
                break

        lack = TCP(sport=self.src_port, dport=self.dest_port, flags='A',
                   seq=l_seq, ack=r_seq)
        self.outgoing_packets.append(lack)
        fack = TCP(sport=self.src_port, dport=self.dest_port, flags='FA',
                   seq=l_seq, ack=r_seq)
        self.outgoing_packets.append(fack)

        self.log.info("Closed connection to %s:%d", self.dest_host, self.dest_port)

    def receive(self, packet):
        self.tunnel_in_queue.put(packet)


class SOCKS5Server:
    def __init__(self, host, port):
        self.log = logging.getLogger('SOCKS5')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(100)

        self.server_addr = ipaddress.IPv4Address(host)
        self.server_port = port

        self.connections = dict()

    def find_free_port(self):
        usable = list(range(1024, 65535))
        random.shuffle(usable)
        for p in usable:
            if p not in self.connections:
                return p
        raise Exception("Too many connections, no free port")

    def handle_connection(self, sock, stream):
        version = stream.read(1)[0]
        assert version == 5

        command = stream.read(1)[0]
        reserved = stream.read(1)[0]
        address_type = stream.read(1)[0]

        if address_type == 1:
            data = stream.read(4)
            address = '.'.join(str(b) for b in data)
        elif address_type == 3:
            length = stream.read(1)[0]
            try:
                address = socket.gethostbyname(stream.read(length).decode('utf-8'))
            except socket.gaierror:
                response = b'\x05\x04\x00\x01'
                response += self.server_addr.packed
                response += self.server_port.to_bytes(2, 'big')
                sock.sendall(response)
                return
        elif address_type == 4:
            data = stream.read(16)
            address = ':'.join('%x' % b for b in data)
        else:
            raise Exception("Got unsupported address type: 0x%x" % address_type)

        dest_host = address
        dest_port = int.from_bytes(stream.read(2), 'big')

        if command == 1:
            # CONNECT
            response = b'\x05\x00\x00\x01'
            response += self.server_addr.packed
            response += self.server_port.to_bytes(2, 'big')
            sock.sendall(response)

            port = self.find_free_port()

            self.log.info("Opening connection from port %d to %s:%d",
                          port, dest_host, dest_port)
            c = SOCKS5Connection(self, sock, port, dest_host, dest_port)
            c.start()
            self.connections[port] = c

        elif command == 2:
            # BIND
            raise NotImplementedError()
        elif command == 3:
            # UDP
            raise NotImplementedError()
        else:
            raise Exception("Got unsupported command: 0x%x" % address_type)

    def __call__(self, client):
        while True:
            incoming = client.recv_data()
            if not incoming:
                break

            ip = incoming
            tcp = incoming.payload
            if not isinstance(tcp, TCP):
                self.log.debug("Ignored: not TCP")
                continue
            local_port = tcp.dport

            if local_port not in self.connections:
                self.log.debug("Ignored: no connection at port %d", local_port)
                continue

            c = self.connections[local_port]
            if not c or not c.running:
                self.log.debug("Ignored: dead connection at port %d", local_port)
                continue

            if ip.src != c.dest_host:
                self.log.debug("Ignored: connection host not matching on port %d (%s / %s)",
                               local_port, ip.src, c.dest_host)
                continue

            data = bytes(tcp.payload)
            self.log.debug("Received %d bytes -> port %d", len(data), local_port)
            c.receive(tcp)

        for local_port, c in self.connections.items():
            for packet in c.outgoing_packets:
                self.log.debug("Sending packet from port %d, %r", local_port, packet)
                p = IP(src=client.tunnel_ipv4, dst=c.dest_host) / packet
                client.send_data(bytes(p))
            c.outgoing_packets = []

        try:
            self.sock.settimeout(0.1)
            rsock, _ = self.sock.accept()

            # Handle new connections
            hello = rsock.recv(2)
            assert hello[0] == 5
            methods = rsock.recv(hello[1])

            rsock.sendall(b'\x05\x00')

            buffer = rsock.recv(2048)
            print(repr(buffer))
            if buffer:
                self.handle_connection(rsock, io.BytesIO(buffer))
        except socket.timeout:
            pass


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format="%(levelname)-5s:%(name)-8s: %(message)s")

    parser = ArgumentParser()
    parser.add_argument('config_file', help="OpenVPN configuration file")
    parser.add_argument('host')
    parser.add_argument('port', type=int, default=9000)
    parser.add_argument('-i', dest='interval', default=1, metavar='interval', type=int)
    parser.add_argument('-W', dest='timeout', default=5, metavar='timeout', type=int)
    parser.add_argument('-c', dest='count', default=0, metavar='count', type=int)

    args = parser.parse_args()
    c = Client(Settings.from_file(args.config_file), SOCKS5Server(args.host, args.port))
    c.run()

if __name__ == '__main__':
    main()

