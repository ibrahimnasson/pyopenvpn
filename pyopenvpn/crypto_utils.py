"""
OpenVPN SSL stuff
"""
import hashlib
import hmac
import logging
import random

log = logging.getLogger("crypto")


def shex(bs):
    return ''.join('%02x' % b for b in bs)


def getrandbytes(n):
    # FIXME: use a CSPRNG
    return random.getrandbits(n * 8).to_bytes(n, 'big')


class KeySource:
    """ Random data used to make keys. """
    def __init__(self, random1, random2, pre_master):
        """ Use remote() or local() """
        self.random1 = random1
        self.random2 = random2
        self.pre_master = pre_master

    def to_bytes(self):
        return self.pre_master + self.random1 + self.random2

    @classmethod
    def remote(cls, r1, r2):
        return cls(r1, r2, None)

    @classmethod
    def local(cls):
        return cls(getrandbytes(32), getrandbytes(32), getrandbytes(48))


def _prf(secret, label, client_seed, server_seed, client_sid, server_sid, olen):
    """ ssl.c tls1_PRF """
    seed = label + client_seed + server_seed

    if client_sid:
        seed += client_sid
    if server_sid:
        seed += server_sid

    return _tls1_prf(seed, secret, olen)


def _tls1_prf(label, sec, olen):
    """ ssl.c tls1_PRF """
    S1 = sec[0:len(sec) // 2]
    S2 = sec[len(sec) // 2:]

    out1 = _tls1_hash(hashlib.md5, S1, label, olen)
    out2 = _tls1_hash(hashlib.sha1, S2, label, olen)

    out = bytes(o1 ^ o2 for (o1, o2) in zip(out1, out2))
    log.debug("prf out: %s", shex(out))
    return out


def _tls1_hash(md, sec, seed, olen):
    """ ssl.c tls1_P_hash """
    A1 = hmac.new(key=sec, msg=seed, digestmod=md).digest()

    chunk = md().digest_size

    log.debug("tls_hash sec: %s", shex(sec))
    log.debug("tls_hash seed: %s", shex(seed))

    i = 0
    out = bytearray()
    while True:
        ctx = hmac.new(key=sec, digestmod=md)
        ctx_tmp = hmac.new(key=sec, digestmod=md)
        ctx.update(A1)
        ctx_tmp.update(A1)
        ctx.update(seed)

        if olen > chunk:
            out[(i * chunk):((i + 1) * chunk)] = ctx.digest()
            olen -= chunk
            i += 1
            A1 = ctx_tmp.digest()
        else:
            A1 = ctx.digest()
            out[(i * chunk):((i + 1) * chunk)] = A1
            break
    log.debug("tls_hash out: %s", shex(out))

    return bytes(out)
