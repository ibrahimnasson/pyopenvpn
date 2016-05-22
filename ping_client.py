#!/bin/python3
import logging
from argparse import ArgumentParser
from datetime import datetime, timedelta
from scapy.all import *

from pyopenvpn import Client, Settings


class PingClient:
    def __init__(self, args):
        self.host = args.host
        self.interval = timedelta(seconds=args.interval)
        self.timeout = timedelta(seconds=args.timeout)
        self.count = args.count
        print("Pinging %s..." % self.host)

        self.pings = []

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

            seq = in_icmp.seq
            if seq >= len(self.pings):
                continue

            ttl = incoming.ttl
            time = (datetime.now() - self.pings[seq]['time']).total_seconds() * 1000

            self.pings[seq]['received'] = True
            print('reply from %s: icmp_seq=%d ttl=%d time=%.1fms' %
                  (self.host, seq, ttl, time))

            if self.count > 0 and len(self.pings) >= self.count:
                client.stop()
                return

        if self.pings:
            if (datetime.now() - self.pings[-1]['time']) > self.timeout \
               and self.pings[-1]['received'] is None:
                print('timeout')
                self.pings[-1]['received'] = False

                if self.count > 0 and len(self.pings) >= self.count:
                    client.stop()
                    return

        if not self.pings or (datetime.now() - self.pings[-1]['time']) > self.interval:
            p = IP(src=client.tunnel_ipv4, dst=self.host) / ICMP(seq=len(self.pings))
            client.send_data(p)
            self.pings.append({'time': datetime.now(), 'received': None})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)-5s:%(name)-8s: %(message)s")

    parser = ArgumentParser()
    parser.add_argument('config_file', help="OpenVPN configuration file")
    parser.add_argument('host', help="Remote host to ping")
    parser.add_argument('-i', dest='interval', default=1, metavar='interval', type=int)
    parser.add_argument('-W', dest='timeout', default=5, metavar='timeout', type=int)
    parser.add_argument('-c', dest='count', default=0, metavar='count', type=int)

    args = parser.parse_args()
    c = Client(Settings.from_file(args.config_file), PingClient(args))
    c.run()

