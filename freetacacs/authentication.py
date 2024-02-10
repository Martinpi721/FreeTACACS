"""
Module implements TACACS+ authentication packets

Classes:
    TACACSPlusAuthenStart
    TACACSPlusAuthenReply

Functions:
    None
"""
import struct
import logging
from dataclasses import dataclass
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet

log = logging.getLogger(__name__)


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

    def __init__(self, *args, **kwargs):
        """Initialise a TACACS+ Authentication Start packet body

        Args:
          None
        Exceptions:
          None
        Returns:
          None
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

        # Extend our parent class __init__ method
        super().__init__(*args, **kwargs)

        # Initialise the packet body fields
        self._action = None
        self._priv_lvl = None
        self._authen_type = None
        self._service = None
        self._user_len = None
        self._port_len = None
        self._rem_addr_len = None
        self._data_len = None


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

        fields = {}

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            self._action, self._priv_lvl = struct.unpack('BB', body.read(2))
            self._authen_type, self._service = struct.unpack('BB', body.read(2))

            (self._user_len,
             self._port_len,
             self._rem_addr_len,
             self._data_len) = struct.unpack('BBBB', body.read(4))

            self._user = body.read(self._user_len).decode('UTF-8')
            self._port = body.read(self._port_len).decode('UTF-8')
            self._remote_address = body.read(self._rem_addr_len).decode('UTF-8')
            self._data = body.read(self._data_len).decode('UTF-8')
        except ValueError as e:
            raise ValueError('Unable to decode AuthenSTART packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        # Convert authentication action flag codes back to human readable strings
        try:
            result = filter(lambda item: item[1] == self._action,
                                     flags.TAC_PLUS_AUTHEN_ACTIONS.items())
            self._action = list(result)[0][0]

            # Convert priveledge level flag codes back to human readable strings
            result = filter(lambda item: item[1] == self._priv_lvl,
                                         flags.TAC_PLUS_PRIV_LVL.items())
            self._priv_lvl = list(result)[0][0]

            # Convert authentication type flag codes back to human readable
            # strings
            result = filter(lambda item: item[1] == self._authen_type,
                                         flags.TAC_PLUS_AUTHEN_TYPES.items())
            self._authen_type = list(result)[0][0]

            # Convert authentication service flag codes back to
            # human readable strings
            result = filter(lambda item: item[1] == self._service,
                                         flags.TAC_PLUS_AUTHEN_SVC.items())
            self._service = list(result)[0][0]
        except IndexError as e:
            raise ValueError('Unable to decode AuthenSTART packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        return AuthenStartFields(self._action, self._priv_lvl, self._authen_type,
                                 self._service, self._user, self._port,
                                 self._remote_address, self._data)


    def __str__(self):
        """String representation of the TACACS+ packet

        Args:
          None
        Exceptions:
          None
        Returns:
          packet(str): containing the TACACS+ packet body
        """

        # Build the string representation
        packet = f'action: {self._action}, priv_lvl: {self._priv_lvl},' \
                 f' authen_type: {self._authen_type}, service: {self._service},' \
                 f' user_len: {self._user_len}, port_len: {self._port_len},' \
                 f' rem_addr_len: {self._rem_addr_len}, data_len: {self._data_len},' \
                 f' user: {self._user}, port: {self._port},' \
                 f' rem_addr: {self._remote_address}, data: {self._data}'

        return packet


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

        # Extend our parent class __init__ method
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


