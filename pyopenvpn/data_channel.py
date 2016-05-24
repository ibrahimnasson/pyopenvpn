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


class CipherBase:
    DEFAULT_KEYSIZE_BITS = None

    def __init__(self, client):
        self.keysize = client.settings['keysize']
        if self.keysize:
            self.keysize = int(self.keysize)
        else:
            assert self.DEFAULT_KEYSIZE_BITS is not None
            self.keysize = self.DEFAULT_KEYSIZE_BITS

        if self.keysize % 8 != 0 or self.keysize > 512 or self.keysize < 64:
            raise Exception("Invalid keysize: %d" % self.keysize)

        self.keysize_bytes = self.keysize // 8

    def encrypt(self, key, iv, plaintext):
        raise NotImplementedError()

    def decrypt(self, key, iv, ciphertext):
        raise NotImplementedError()


class BlowfishCBCCipher(CipherBase):
    DEFAULT_KEYSIZE_BITS = 128

    def encrypt(self, key, iv, plaintext):
        cipher = Blowfish.new(key=key[:self.keysize_bytes], IV=iv, mode=Blowfish.MODE_CBC)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    def decrypt(self, key, iv, ciphertext):
        cipher = Blowfish.new(key=key[:self.keysize_bytes], IV=iv, mode=Blowfish.MODE_CBC)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext


class HMACBase:
    SIZE = None

    def __init__(self, client):
        pass

    def do(self, key, data):
        raise NotImplementedError()


class SHA1HMAC(HMACBase):
    HASH_LENGTH = 20

    def hash(self, key, data):
        hmac_ = hmac.new(key=key[:self.HASH_LENGTH],
                         msg=data,
                         digestmod=hashlib.sha1)
        return hmac_.digest()


class DataChannel(Channel):
    OPCODES = (protocol.P_DATA_V1, )

    def __init__(self, client):
        self.log = logging.getLogger("DataChan")
        self.c = client
        self.packet_id = 0

        # Packets auth'd and decrypted, ready for the user to read then
        self.out_queue = []

        ciphers = {
            'BF-CBC': BlowfishCBCCipher,
        }
        hmacs = {
            'SHA1': SHA1HMAC,
        }

        self.cipher = ciphers[client.settings['cipher']](self.c)
        self.hmac = hmacs[client.settings['auth']](self.c)

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

        self.cipher_key_local, self.hmac_key_local = keys[0:64], keys[64:128]
        self.cipher_key_remote, self.hmac_key_remote = keys[128:192], keys[192:256]

        self.log.info("cipher_key_local:  " + shex(self.cipher_key_local))
        self.log.info("cipher_key_remote: " + shex(self.cipher_key_remote))
        self.log.info("hmac_key_local:    " + shex(self.hmac_key_local))
        self.log.info("hmac_key_remote:   " + shex(self.hmac_key_remote))

    def encrypt(self, plaintext):
        iv = getrandbytes(8)

        n = 8 - (len(plaintext) % 8)
        padded = plaintext + b''.join(bytes([n]) for _ in range(n))

        ciphertext = self.cipher.encrypt(self.cipher_key_local, iv, padded)

        hmac_ = self.hmac.hash(self.hmac_key_local, iv + ciphertext)
        self.log.debug("encrypted %d bytes (%d pt bytes): iv=%s hmac=%s",
                       len(ciphertext), len(plaintext), shex(iv), shex(hmac_))
        return hmac_ + iv + ciphertext

    def decrypt(self, data):
        if len(data) < 28:
            raise InvalidPacketError("Packet too short (%d bytes)" % len(data))

        hmac_ = data[:self.hmac.HASH_LENGTH]
        iv = data[self.hmac.HASH_LENGTH:self.hmac.HASH_LENGTH + 8]
        ciphertext = data[self.hmac.HASH_LENGTH + 8:]

        our_hmac = self.hmac.hash(self.hmac_key_remote, iv + ciphertext)
        if not hmac.compare_digest(our_hmac, hmac_):
            self.log.error("cannot decrypt %d bytes: iv=%s hmac=%s local_hmac=%s",
                           shex(iv), shex(hmac_), shex(our_hmac))
            raise InvalidHMACError()

        plaintext = self.cipher.decrypt(self.cipher_key_remote, iv, ciphertext)

        # remove padding
        n = plaintext[-1]
        assert n < len(plaintext) and n < 8
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

