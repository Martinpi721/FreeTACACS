"""
Module implements TACACS+ authentication packets

Classes:
    TACACSPlusAuthenStart
    TACACSPlusAuthenReply

Functions:
    None
"""
import struct
from dataclasses import dataclass
from twisted.logger import Logger
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet


@dataclass
class AuthenStartFields:
    """Defines Authentication Start packet fields"""
    action: int
    priv_lvl: int
    authen_type: int
    service: int
    user: str
    port: str
    remote_address: str
    data: str

    # Validate the data
    def __post_init__(self):
        if not isinstance(self.action,
                          int) and not isinstance(self.action, str):
            raise TypeError('Action should be of type int')

        if not isinstance(self.priv_lvl,
                          int) and not isinstance(self.priv_lvl, str):
            raise TypeError('Priviledge Level should be of type int')

        if not isinstance(self.authen_type,
                          int) and not isinstance(self.authen_type, str):
            raise TypeError('Authentication Type should be of type int')

        if not isinstance(self.service,
                          int) and not isinstance(self.service, str):
            raise TypeError('Service should be of type int')

        if not isinstance(self.user, str):
            raise TypeError('User should be of type string')

        if not isinstance(self.port, str):
            raise TypeError('Port should be of type string')

        if not isinstance(self.remote_address, str):
            raise TypeError('Remote Address should be of type string')

        if not isinstance(self.data, str):
            raise TypeError('Data should be of type string')


class TACACSPlusAuthenStart(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication START packet bodies"""

    # Setup the logger
    log = Logger()


    @property
    def decode(self):
        """Decode a TACAS+ Authentication start packet body

        Args:
          None
        Exceptions:
          ValueError
        Returns:
          fields(dict): containing body field name/value pairs
        """

        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |    action      |    priv_lvl    |  authen_type   |     service    |
        # +----------------+----------------+----------------+----------------+
        # |    user len    |    port len    |  rem_addr len  |    data len    |
        # +----------------+----------------+----------------+----------------+
        # |    user ...
        # +----------------+----------------+----------------+----------------+
        # |    port ...
        # +----------------+----------------+----------------+----------------+
        # |    rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |    data...
        # +----------------+----------------+----------------+----------------+

        fields = {}

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            action, priv_lvl = struct.unpack('BB', body.read(2))
            authen_type, service = struct.unpack('BB', body.read(2))
            user_len, port_len, rem_addr_len, data_len = struct.unpack('BBBB',
                                                                       body.read(4))
            user = body.read(user_len).decode('UTF-8')
            port = body.read(port_len).decode('UTF-8')
            remote_address = body.read(rem_addr_len).decode('UTF-8')
            data = body.read(data_len).decode('UTF-8')
        except ValueError as e:
            raise ValueError('Unable to decode AuthenSTART packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        # Convert authentication action flag codes back to human readable strings
        try:
            result = filter(lambda item: item[1] == action,
                                     flags.TAC_PLUS_AUTHEN_ACTIONS.items())
            action = list(result)[0][0]

            # Convert priveledge level flag codes back to human readable strings
            result = filter(lambda item: item[1] == priv_lvl,
                                         flags.TAC_PLUS_PRIV_LVL.items())
            priv_lvl = list(result)[0][0]

            # Convert authentication type flag codes back to human readable
            # strings
            result = filter(lambda item: item[1] == authen_type,
                                         flags.TAC_PLUS_AUTHEN_TYPES.items())
            authen_type = list(result)[0][0]

            # Convert authentication service flag codes back to
            # human readable strings
            result = filter(lambda item: item[1] == service,
                                         flags.TAC_PLUS_AUTHEN_SVC.items())
            service = list(result)[0][0]
        except IndexError as e:
            raise ValueError('Unable to decode AuthenSTART packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        return AuthenStartFields(action, priv_lvl, authen_type, service, user,
                                 port, remote_address, data)


@dataclass
class AuthenReplyFields:
    """Defines Authentication Reply fields required to create a Reply packet"""
    status: int
    flags: int
    server_msg: str = ''
    data: str = ''

    # Validate the data
    def __post_init__(self):
        if not isinstance(self.status, int):
            raise TypeError('Status should be of type int')

        if not isinstance(self.flags, int):
            raise TypeError('Flags should be of type int')

        if not isinstance(self.server_msg, str):
            raise TypeError('Server Message should be of type string')

        if not isinstance(self.data, str):
            raise TypeError('Data should be of type string')


class TACACSPlusAuthenReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication REPLY packet
    bodies"""

    # Setup the logger
    log = Logger()


    def __init__(self, header, body=six.b(''), fields=AuthenReplyFields(0, 0),
                 secret=None):
        """Initialise a TACAS+ Authentication REPLY packet body

        Initialise a TACACS+ Authentication REPLY packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: status, flags, server_msg
        and data. See RFC8907 for details on contents of each.

        Args:
          header(obj): instance of a TACACSPlusHeader class
          body(bytes): byte encoded TACACS+ packet body
          fields(dataclass): fields used to create packet body
          secret(str): client/server shared secret
        Exceptions:
          TypeError
          ValueError
        Returns:
          None
        """

        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |     status     |      flags     |        server_msg len           |
        # +----------------+----------------+----------------+----------------+
        # |           data len              |        server_msg ...
        # +----------------+----------------+----------------+----------------+
        # |           data ...
        # +----------------+----------------+

        # Extend the Packet base class
        super().__init__(header, body, secret)

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dict doesn't contain these keys then we are decoding a REPLY
        # rather than building a REPLY packet
        try:
            self._status = fields.status
            self._flags = fields.flags
            self._server_msg = fields.server_msg
            self._data = fields.data
        except TypeError:
            raise

        # Build packet structure
        try:
            # B = unsigned char
            self._body = struct.pack('BB', self._status, self._flags)
            # !H = network-order (big-endian) unsigned short
            self._body += struct.pack('!HH', len(self._server_msg), len(self._data))

            # Byte encode
            server_msg = six.b(self._server_msg)
            data = six.b(self._data)

            # s = char[]
            for value in (server_msg, data):
                self._body += struct.pack(f'{len(value)}s', value)
        except struct.error as e:
            raise ValueError('Unable to encode AuthenReply packet. Required' \
                             ' arguments status and flags must be integers') from e
        except TypeError as e:
            raise ValueError('Unable to encode AuthenReply packet. Required' \
                             ' arguments server_msg and data must be strings') from e

        # Set the packet body length in the header
        self._header.length = len(self._body)

        return None
