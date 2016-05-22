#!/bin/python3
import ssl
import random
import logging

from . import protocol
from .crypto_utils import shex, KeySource
from .common import Channel, InvalidPacketError, AuthFailed, ProtocolLogicError
from .settings import Settings


def encode_string(s):
    data = bytes()
    data += (len(s) + 1).to_bytes(2, 'big')
    data += s.encode('utf-8') + b"\x00"
    return data


class ControlChannel(Channel):
    """ Control Channel
    Handles:
    - P_CONTROL_HARD_RESET_SERVER_V2
    - P_CONTROL_V1 -> TLS -> Control Channel Messages
    """

    OPCODES = (protocol.P_CONTROL_V1, protocol.P_CONTROL_HARD_RESET_SERVER_V2)

    def __init__(self, client):
        self.log = logging.getLogger("CtrlChan")
        self.c = client

        self.session_id = random.getrandbits(64).to_bytes(8, 'big')
        self.remote_session_id = None
        self.local_pid = 0
        self.tls = None

        self.log.info("Control Channel created")
        self.log.info("local session id: %s", shex(self.session_id))

        super().__init__()

    def init_tls(self):
        self.log.debug("initializing TLS context...")
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        self.tls_in = ssl.MemoryBIO()
        self.tls_out = ssl.MemoryBIO()
        self.tls = self.tls_ctx.wrap_bio(self.tls_in, self.tls_out, False, None)

    def try_handshake(self):
        try:
            self.tls.do_handshake()
            return True
        except ssl.SSLWantReadError:
            pass
        self._sync_tls_out()
        self._sync_tls_in()
        return False

    def send_hard_reset(self):
        self.log.debug("sending HARD_RESET %08x ...", self.local_pid)
        return self._send_p_control(protocol.P_CONTROL_HARD_RESET_CLIENT_V2)

    def send_control_message(self):
        """ "control channel packet", not literally P_CONTROL.
        """
        self.log.info("sending control message...")

        data = b"\x00" * 4
        data += b"\x02"  # key method (2)
        data += self.c.local_key_source.to_bytes()

        data += encode_string(self.c.settings.get_options())
        data += encode_string(self.c.username or '')
        data += encode_string(self.c.password or '')

        self.tls.write(data)
        self._sync_tls_out()

    def send_push_request(self):
        self.log.debug("sending PUSH_REQUEST...")
        self.tls.write(b"PUSH_REQUEST\x00")
        self._sync_tls_out()

    def read_control_message(self, data):
        if len(data) < 71:
            raise InvalidPacketError("Control message too short (%d bytes)" % len(data))

        if data[:4] != b"\x00" * 4:
            raise InvalidPacketError("Invalid control message header: " + shex(data[:4]))

        key_method = data[4]
        if key_method != 2:
            raise ProtocolLogicError("Unsupported key method: %d" % key_method)

        self.log.debug(repr(data))

        offset = 5

        random1 = data[offset:offset + 32]
        offset += 32

        random2 = data[offset:offset + 32]
        offset += 32

        options_len = int.from_bytes(data[offset:offset + 2], 'big') - 1
        offset += 2
        remote_option_string = data[offset:offset + options_len].decode('utf-8')
        self.remote_options = Settings.from_options(remote_option_string)

        # now there should be empty username/password strings
        # but we don't care.
        # FIXME: check they are empty

        self.log.debug("received control message: %d bytes", len(data))
        self.log.debug("remote random1: %s", shex(random1))
        self.log.debug("remote random2: %s", shex(random2))
        self.log.debug("remote options: %s", self.remote_options)

        ro = self.remote_options.copy()
        if 'tls-server' in ro:
            del ro['tls-server']
            ro['tls-client'] = True

        if not ro.items() <= self.c.settings.items():
            self.log.warn("Options doesn't match!")
            self.log.warn("remote options: %s", remote_option_string)
            self.log.warn("local  options: %s", self.c.settings.get_options())

        self.c.remote_key_source = KeySource.remote(random1, random2)
        self.c.on_key_exchanged()

    def _send_p_control_v1(self, data):
        self.log.debug("sending CONTROL_V1 %08x (with %d bytes)...",
                       self.local_pid, len(data))
        return self._send_p_control(protocol.P_CONTROL_V1, ack_pid=None, payload=data)

    def _send_p_control(self, opcode, ack_pid=None, payload=None):
        p = int(opcode << 3).to_bytes(1, 'big')
        p += self.session_id  # 64b
        # p += hmac

        if ack_pid is None:
            ack_pid = []
        elif isinstance(ack_pid, int):
            ack_pid = [ack_pid]

        if ack_pid:
            assert self.remote_session_id is not None

        p += int(len(ack_pid)).to_bytes(1, 'big')
        for pid in ack_pid:
            p += int(pid).to_bytes(4, 'big')
        if ack_pid:
            p += self.remote_session_id

        p += int(self.local_pid).to_bytes(4, 'big')
        self.local_pid += 1

        if payload is not None:
            p += payload

        return self._send(p)

    def read_hard_reset(self, data):
        assert data[0] == 0x40

        if self.remote_session_id is not None:
            if data[1:9] != self.remote_session_id:
                raise InvalidPacketError("Invalid remote session id: %s",
                                         shex(self.remote_session_id))
        else:
            self.remote_session_id = data[1:9]
            self.log.info("learnt remote session id: %s", shex(self.remote_session_id))

        ack_arr_len = data[9]
        ack_arr = [int.from_bytes(data[(10 + i * 4):(10 + (i + 1) * 4)], 'big')
                   for i in range(0, ack_arr_len)]
        offset = 10 + len(ack_arr) * 4
        if ack_arr:
            local_session_id = data[offset:offset + 8]
            offset += 8
            if local_session_id != self.session_id:
                raise InvalidPacketError("Invalid local session id in ACK: " +
                                         shex(local_session_id) +
                                         "(local: " + shex(self.session_id) + ")")

        packet_id = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4

        self.log.debug("received HARD_RESET %08x ...", packet_id)
        for ack in ack_arr:
            self.log.debug("ACK'd packet: %08x", ack)

        return packet_id

    def read_control(self, data):
        # FIXME: it shares most of the function with read_hard_reset
        assert data[0] == 0x20

        if self.remote_session_id is not None:
            if data[1:9] != self.remote_session_id:
                raise InvalidPacketError("Invalid remote session id: %s",
                                         shex(self.remote_session_id))
        else:
            self.remote_session_id = data[1:9]
            self.log.info("learnt remote session id: %s", shex(self.remote_session_id))

        ack_arr_len = data[9]
        ack_arr = [int.from_bytes(data[(10 + i * 4):(10 + (i + 1) * 4)], 'big')
                   for i in range(0, ack_arr_len)]
        offset = 10 + len(ack_arr) * 4
        if ack_arr:
            local_session_id = data[offset:offset + 8]
            offset += 8
            if local_session_id != self.session_id:
                raise InvalidPacketError("Invalid local session id in ACK: " +
                                         shex(local_session_id) +
                                         "(local: " + shex(self.session_id) + ")")

        packet_id = int.from_bytes(data[offset:offset + 4], 'big')
        offset += 4

        payload = data[offset:]

        self.log.debug("received P_CONTROL %08x (with %d bytes) ...",
                       packet_id, len(payload))
        for ack in ack_arr:
            self.log.debug("ACK'd packet: %08x", ack)

        return (packet_id, ack_arr, payload)

    def _sync_tls_out(self):
        if self.tls_out.pending > 0:
            t = self.tls_out.read(8192)
            self.log.debug("TLS data out (%d bytes):", len(t))
            self._send_p_control_v1(t)

    def _sync_tls_in(self):
        if not self.queue:
            return
        data = self.queue.pop()
        opcode = data[0] >> 3

        if opcode == protocol.P_CONTROL_V1:
            self.log.debug("TLS data in (%d bytes):", len(data))
            pid, ack_arr, payload = self.read_control(data)
            self.c.send_ack(pid)
            self.tls_in.write(payload)
        else:
            raise InvalidPacketError("Received unknown opcode %d" % opcode)

    def handle_in(self):
        self._sync_tls_in()

        try:
            data = self.tls.read()
        except ssl.SSLWantReadError:
            return

        if data.startswith(b'\x00\x00\x00\x00'):
            self.read_control_message(data)
        elif data.startswith(b'PUSH_REPLY'):
            self.c.on_push(data)
        elif data.startswith(b'AUTH_FAILED'):
            raise AuthFailed()
        else:
            self.log.warn("Unknown control packet: %r", data)


