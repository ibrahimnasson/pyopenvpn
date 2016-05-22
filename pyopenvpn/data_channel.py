#!/bin/python3
import hashlib
import hmac
import logging
from Crypto.Cipher import Blowfish

from . import protocol
from .crypto_utils import _prf, shex, getrandbytes
from .common import Channel, InvalidHMACError, InvalidPacketError


PING_DATA = bytes([
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
])


class DataChannel(Channel):
    OPCODES = (protocol.P_DATA_V1, )

    def __init__(self, client):
        self.log = logging.getLogger("DataChan")
        self.c = client
        self.packet_id = 0

        # Packets auth'd and decrypted, ready for the user to read then
        self.out_queue = []

        super().__init__()

    def setup(self):
        master = _prf(self.c.local_key_source.pre_master,
                      b"OpenVPN master secret",
                      self.c.local_key_source.random1,
                      self.c.remote_key_source.random1,
                      None, None, 48)

        keys = _prf(master, b"OpenVPN key expansion",
                    self.c.local_key_source.random2,
                    self.c.remote_key_source.random2,
                    self.c.ctrl.session_id,
                    self.c.ctrl.remote_session_id,
                    256)

        self.cipher1, self.hmac1 = keys[0:64], keys[64:128]
        self.cipher2, self.hmac2 = keys[128:192], keys[192:256]

        self.log.info("cipher1: " + shex(self.cipher1))
        self.log.info("cipher2: " + shex(self.cipher2))
        self.log.info("hmac1  : " + shex(self.hmac1))
        self.log.info("hmac2  : " + shex(self.hmac2))

    def data_hmac(self, key, data):
        return hmac.new(key=key, msg=data, digestmod=hashlib.sha1).digest()

    def encrypt(self, plaintext):
        iv = getrandbytes(8)

        n = 8 - (len(plaintext) % 8)
        padded = plaintext + b''.join(bytes([n]) for _ in range(n))

        cipher = Blowfish.new(key=self.cipher1[:16], IV=iv, mode=Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(padded)

        hmac_ = self.data_hmac(self.hmac1[:20], iv + ciphertext)
        self.log.debug("encrypted %d bytes (%d pt bytes): iv=%s hmac=%s",
                       len(ciphertext), len(plaintext), shex(iv), shex(hmac_))
        return hmac_ + iv + ciphertext

    def decrypt(self, data):
        if len(data) < 28:
            raise InvalidPacketError("Packet too short (%d bytes)" % len(data))

        hmac_ = data[:20]
        iv = data[20:28]
        ciphertext = data[28:]

        our_hmac = self.data_hmac(self.hmac2[:20], iv + ciphertext)
        if not hmac.compare_digest(our_hmac, hmac_):
            self.log.error("cannot decrypt %d bytes: iv=%s hmac=%s local_hmac=%s",
                           shex(iv), shex(hmac_), shex(our_hmac))
            raise InvalidHMACError()

        cipher = Blowfish.new(key=self.cipher2[:16], IV=iv, mode=Blowfish.MODE_CBC)
        plaintext = cipher.decrypt(ciphertext)

        # remove padding
        n = plaintext[-1]
        plaintext = plaintext[:-n]

        self.log.debug("decrypted %d bytes (%d pt bytes): iv=%s hmac=%s",
                       len(ciphertext), len(plaintext), shex(iv), shex(hmac_))
        return plaintext

    def send(self, payload):
        self.packet_id += 1

        plaintext = bytes()
        plaintext += self.packet_id.to_bytes(4, 'big')
        plaintext += b'\xfa'  # no compression
        plaintext += payload

        self._send(b'\x30' + self.encrypt(plaintext))

    def recv(self):
        if not self.out_queue:
            return None
        return self.out_queue.pop(0)

    def handle_in(self):
        """ pop stuff and try to decrypt """
        if self.queue:
            packet = self.queue.pop()
            assert packet[0] == 0x30
            data = packet[1:]
            self.log.debug("raw input: %r", data)
            plaintext = self.decrypt(data)

            packet_id = plaintext[:4]
            # FIXME do stuff with packet_id
            compression = plaintext[4]

            # http://build.openvpn.net/doxygen/html/comp_8h_source.html
            assert compression == 0xfa  # no compression

            payload = plaintext[5:]
            self.out_queue.append(payload)
            self.log.debug("data: %r", payload)

            if payload == PING_DATA:
                self.log.debug("PING received, replied")
                self.send(PING_DATA)
                return

