
class ClientError(Exception):
    pass


class ProtocolError(ClientError):
    """ Error communicating with the OpenVPN server """
    pass


class InvalidPacketError(ProtocolError):
    """ Packet that doesn't make any sense and cannot be read correctly. """
    pass


class InvalidHMACError(InvalidPacketError):
    pass


class ProtocolLogicError(ProtocolError):
    """ Unsupported stuff, unexpected packets, ...
    Things that are readable but not supported by this implementation.
    """
    pass


class AuthFailed(ClientError):
    pass


class ConfigError(ClientError):
    pass


class Channel:
    def __init__(self):
        self.queue = []

    def push_packet(self, packet):
        self.queue.append(packet)

    def _send(self, packet):
        self.c._send(packet)

