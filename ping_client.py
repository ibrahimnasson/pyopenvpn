#!/bin/python3
import sys
import logging
from datetime import datetime, timedelta
from scapy.all import *

from pyopenvpn import Client, Settings

class PingClient:
    def __init__(self, host):
        self.host = host
        print("Pinging %s..." % host)

        self.last_ping = None
        self.seq = 0

    def __call__(self, client):
        while True:
            incoming = client.recv_data()
            if not incoming:
                break

            if incoming.src != self.host:
                continue
            if not isinstance(incoming.payload, ICMP):
                continue
            in_icmp = incoming.payload
            if in_icmp.type != 0:
                continue
            if not self.last_ping:
                continue

            seq = in_icmp.seq
            ttl = incoming.ttl
            time = (datetime.now() - self.last_ping).total_seconds() * 1000
            print('reply from %s: icmp_seq=%d ttl=%d time=%.1fms' %
                  (self.host, seq, ttl, time))

        if not self.last_ping or (datetime.now() - self.last_ping) > timedelta(seconds=1):
            p = IP(src=client.tunnel_ipv4, dst=self.host) / ICMP(seq=self.seq)
            client.send_data(p)
            self.last_ping = datetime.now()
            self.seq += 1


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-5s:%(name)-8s: %(message)s")

    if len(sys.argv) != 3:
        print("Usage: %s <config file> <target ip address>" % sys.argv[0])
        exit(1)

    c = Client(Settings.from_file(sys.argv[1]), PingClient(sys.argv[2]))
    c.run()

