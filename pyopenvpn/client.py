import socket
import time
import logging
import getpass
import scapy.layers.inet

from .crypto_utils import KeySource
from .data_channel import DataChannel
from .control_channel import ControlChannel
from .settings import Settings, DEFAULT_SETTINGS
from .common import ConfigError
from . import protocol


class State:
    NOTHING = 0
    CONTROL_CHANNEL_OPEN = 1
    CONTROL_MESSAGE_SENT = 2
    KEY_EXCHANGED = 3
    PULL_REQUEST_SENT = 4
    OPTIONS_PUSHED = 5
    INITIALIZED = 6


class Client:
    def __init__(self, settings, callback, userpass=None):
        """ Init the OpenVPN client.
        settings is a dict or Settings object.
        callback(client) will be called in the event loop and can be used to interract
        with the tunnel.
        userpass=None is a way to override auth-user-pass settings, since it
        requires a file and that's bad for most scripts using this.
        """

        self.log = logging.getLogger("Client")
        self.local_key_source = KeySource.local()
        self.remote_key_source = None
        self.state = 0
        self.callback = callback

        self.tunnel_ipv4 = None
        self.tunnel_netmask = None

        self.settings = Settings()
        self.settings.update(DEFAULT_SETTINGS)
        self.settings.update(settings)

        def assert_opt(key, expected):
            value = self.settings[key]
            if value != expected:
                raise ConfigError("%s: Unsupported settings value: %r" % (key, value))

        # Make sure we're using supported settings
        # also a TODO-list of things to support
        assert_opt('dev-type', 'tun')
        assert_opt('proto', 'UDPv4')
        assert_opt('cipher', 'BF-CBC')
        assert_opt('auth', 'SHA1')
        assert_opt('keysize', '128')
        assert_opt('key-method', '2')
        assert_opt('tls-client', True)

        aup = self.settings.get('auth-user-pass')
        if userpass:
            self.username, self.password = userpass
        elif aup is True:
            self.username = input("OpenVPN Username: ")
            self.password = getpass.getpass("OpenVPN Password: ")
        elif aup:
            with open(aup) as f:
                lines = list(f)
                assert len(lines) >= 2
                self.username = lines[0].strip()
                self.password = lines[1].strip()
        else:
            self.username, self.password = None, None

        # TODO: handle multiple remote lines
        remote = self.settings.get('remote')
        if not isinstance(remote, str):
            raise ConfigError("Invalid remote config item")
        host, port, proto, *_ = remote.split(' ') + [None, None]
        self.host = host
        self.port = int(port) if port else 1194
        self.proto = proto or 'udp'

    def run(self):
        """ Connect and run the main event loop. """

        self.log.info("connecting to %s:%d UDP...", self.host, self.port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.host, self.port))

        self.ctrl = ControlChannel(self)
        self.data = DataChannel(self)

        self.ctrl.send_hard_reset()
        id = self.ctrl.read_hard_reset(self._recv())
        self.send_ack(id)

        self.log.info("initializing tls context...")
        self.ctrl.init_tls()

        self.socket.setblocking(False)

        self.log.info("sending hello...")
        while True:
            if self.ctrl.try_handshake():
                break
            self.handle_in()

        self.log.info("handshake finished!")
        self._debug_ios()

        self.init_state = State.CONTROL_CHANNEL_OPEN

        # Control channel ready
        # Initialization loop:
        while True:
            # Anything special to do?
            if self.init_state == State.CONTROL_CHANNEL_OPEN:
                self.log.info("Control channel open, sending auth...")
                self.ctrl.send_control_message()
                self.init_state = State.CONTROL_MESSAGE_SENT
            elif self.init_state == State.KEY_EXCHANGED:
                self.log.info("Key exchange complete, pulling config...")
                self.ctrl.send_push_request()
                self.init_state = State.PULL_REQUEST_SENT
            elif self.init_state == State.OPTIONS_PUSHED:
                self.data.setup()
                self.log.info("Initialization complete")
                self.init_state = State.INITIALIZED
            elif self.init_state == State.INITIALIZED:
                self.callback(self)

            # Anyway, I/Os, passing data to stuff, ...
            self.handle_in()
            self.ctrl.handle_in()
            self.data.handle_in()
            self._debug_ios()

            # TODO: something better
            time.sleep(0.001)

        self.log.info('meow .-.')

    def on_key_exchanged(self):
        assert self.init_state == State.CONTROL_MESSAGE_SENT
        self.init_state = State.KEY_EXCHANGED

    def on_push(self, data):
        assert self.init_state == State.PULL_REQUEST_SENT
        self.init_state = State.OPTIONS_PUSHED

        print(repr(data))
        self.settings.update(Settings.from_push(data[:-1].decode('utf-8')))

        ifconfig = self.settings.get('ifconfig').split(' ')
        if len(ifconfig) == 2:
            self.tunnel_ipv4 = ifconfig[0]
            self.tunnel_netmask = ifconfig[1]
        else:
            raise Exception("Unknown ifconfig format")

        self.log.info("Received ifconfig: %s/%s", self.tunnel_ipv4, self.tunnel_netmask)

    def handle_in(self):
        try:
            data = self.socket.recv(4096)
        except BlockingIOError:
            return False
        if not data:
            return False

        opcode = data[0] >> 3

        # Handled here
        if opcode == protocol.P_ACK_V1:
            self.log.debug("Received ACK")
            # FIXME: do something with this ack

        # Handled by channel
        elif opcode in ControlChannel.OPCODES:
            self.ctrl.push_packet(data)
        elif opcode in DataChannel.OPCODES:
            self.data.push_packet(data)

        # WTF
        else:
            raise Exception("Cannot dispatch packet: %x (opcode %d)" % (data[0], opcode))

        return True

    def send_ack(self, ack_pid):
        self.log.debug("ACK'ing packet %08x ...", ack_pid)
        assert self.ctrl.remote_session_id is not None

        p = b'\x28'  # P_ACK_V1 0x05 (5b) + 0x0 (3b)
        p += self.ctrl.session_id

        p += b"\x01"
        p += int(ack_pid).to_bytes(4, 'big')
        p += self.ctrl.remote_session_id
        return self._send(p)

    def send_data(self, data):
        """ Simple way to send data through the tunnel. """
        self.data.send(bytes(data))

    def recv_data(self, decode=True):
        """ Simple way to receive data from the tunnel. """
        data = self.data.recv()
        if data is None:
            return None
        if decode:
            return scapy.layers.inet.IP(data)
        return data

    def _send(self, data):
        self.socket.send(data)

    def _recv(self):
        return self.socket.recv(8192)

    def _debug_ios(self):
        return
        print("[bio: %d in/%d out] [queue: ctrl=%d/data=%d] [tls pending: %d]" % (
              self.ctrl.tls_in.pending, self.ctrl.tls_out.pending,
              len(self.ctrl.queue), len(self.data.queue),
              self.ctrl.tls.pending()))
