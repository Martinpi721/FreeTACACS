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
    priv_lvl: int = 0x00
    authen_type: int = 0x00
    authen_service: int = 0x00
    user: str = ''
    port: str = ''
    remote_address: str = ''
    data: str = ''

    # Validate the data
    def __post_init__(self):
        if not isinstance(self.action, int):
            raise TypeError('Action should be of type int')

        if not isinstance(self.priv_lvl, int):
            raise TypeError('Priviledge Level should be of type int')

        if not isinstance(self.authen_type, int):
            raise TypeError('Authentication Type should be of type int')

        if not isinstance(self.authen_service, int):
            raise TypeError('Authentication Service should be of type int')

        if not isinstance(self.user, str):
            raise TypeError('User should be of type string')

        if not isinstance(self.port, str):
            raise TypeError('Port should be of type string')

        if not isinstance(self.remote_address, str):
            raise TypeError('Remote Address should be of type string')

        if not isinstance(self.data, str):
            raise TypeError('Data should be of type string')


    def __str__(self):
        """String representation of the auth start fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the auth start fields
        """

        # Convert action codes back to human readable strings
        result = filter(lambda item: item[1] == self.action,
                                 flags.TAC_PLUS_AUTHEN_ACTIONS.items())
        action = list(result)[0][0]

        # Convert priveledge level flag codes back to human readable strings
        result = filter(lambda item: item[1] == self.priv_lvl,
                                     flags.TAC_PLUS_PRIV_LVL.items())
        priv_lvl = list(result)[0][0]

        # Convert authentication type flag codes back to human readable
        # strings
        result = filter(lambda item: item[1] == self.authen_type,
                                     flags.TAC_PLUS_AUTHEN_TYPES.items())
        authen_type = list(result)[0][0]

        # Convert authentication service flag codes back to
        # human readable strings
        result = filter(lambda item: item[1] == self.authen_service,
                                     flags.TAC_PLUS_AUTHEN_SVC.items())
        authen_service = list(result)[0][0]

        # Build the string representation
        fields = f'action: {action}, priv_lvl: {priv_lvl},' \
                 f' authen_type: {authen_type}, authen_service: {authen_service},' \
                 f' user: {self.user}, port: {self.port},' \
                 f' remote_address: {self.remote_address}, data: {self.data}'

        return fields


class TACACSPlusAuthenStart(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication START packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AuthenStartFields(action=0x01),
                 secret=None):
        """Initialise a TACACS+ Authentication Start packet body

        Initialise a TACACS+ Authentication START packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: action, priv_lvl, authen_type,
        authen_service, user, port, remote_address and data. See RFC8907 for details on
        contents of each.

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
        # |    action      |    priv_lvl    |  authen_type   | authen_service |
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
        super().__init__(header, body, secret)

        # Initialise the packet body fields
        self._action = None
        self._priv_lvl = None
        self._authen_type = None
        self._authen_service = None
        self._user_len = None
        self._port_len = None
        self._rem_addr_len = None
        self._data_len = None
        self._user = None
        self._port = None
        self._remote_address = None
        self._data = None

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dict doesn't contain these keys then we are decoding a START
        # rather than building a START packet
        try:
            self._action = fields.action
            self._priv_lvl = fields.priv_lvl
            self._authen_type = fields.authen_type
            self._authen_service = fields.authen_service
            self._user = fields.user
            self._user_len = len(self._user)
            self._port = fields.port
            self._port_len = len(self._port)
            self._remote_address = fields.remote_address
            self._rem_addr_len = len(self._remote_address)
            self._data = fields.data
            self._data_len = len(self._data)
        except TypeError:
            raise

        # Build packet structure
        try:
            # B = unsigned char
            self._body = struct.pack('BBBB', self._action, self._priv_lvl,
                                     self._authen_type, self._authen_service)
            # !H = network-order (big-endian) unsigned short
            self._body += struct.pack('BBBB', self._user_len, self._port_len,
                                       self._rem_addr_len, self._data_len)

            # Byte encode
            user = six.b(self._user)
            port = six.b(self._port)
            remote_address = six.b(self._remote_address)
            data = six.b(self._data)

            # s = char[]
            for value in (user, port, remote_address, data):
                self._body += struct.pack(f'{len(value)}s', value)
        except struct.error as e:
            raise ValueError('Unable to encode AuthenStart packet. Required' \
                             ' arguments action, priv_lvl, authen_type and flags' \
                             ' must be integers') from e
        except TypeError as e:
            raise ValueError('Unable to encode AuthenStart packet. Required' \
                             ' arguments user, port, remote_address and data' \
                             ' must be strings') from e

        # Set the packet body length in the header
        self._header.length = len(self._body)

        return None


    @property
    def decode(self):
        """Decode a TACAS+ Authentication start packet body

        Args:
          None
        Exceptions:
          ValueError
        Returns:
          fields(obj): instance of AuthenStartFields dataclass
        """

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            self._action, self._priv_lvl = struct.unpack('BB', body.read(2))
            self._authen_type, self._authen_service = struct.unpack('BB', body.read(2))

            (self._user_len,
             self._port_len,
             self._rem_addr_len,
             self._data_len) = struct.unpack('BBBB', body.read(4))

            self._user = body.read(self._user_len).decode('UTF-8')
            self._port = body.read(self._port_len).decode('UTF-8')
            self._remote_address = body.read(self._rem_addr_len).decode('UTF-8')
            self._data = body.read(self._data_len).decode('UTF-8')
        except ValueError as e:
            raise ValueError('Unable to decode AuthenStart packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        fields = AuthenStartFields(action=self._action,
                                   priv_lvl=self._priv_lvl,
                                   authen_type=self._authen_type,
                                   authen_service=self._authen_service,
                                   user=self._user,
                                   port=self._port,
                                   remote_address=self._remote_address,
                                   data=self._data)

        return fields


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
                 f' authen_type: {self._authen_type}, authen_service:' \
                 f' {self._authen_service}, user_len: {self._user_len},' \
                 f' port_len: {self._port_len}, rem_addr_len:' \
                 f' {self._rem_addr_len}, data_len: {self._data_len},' \
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


    def __str__(self):
        """String representation of the auth reply fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the auth reply fields
        """

        # Convert status codes back to human readable strings
        result = filter(lambda item: item[1] == self.status,
                                 flags.TAC_PLUS_AUTHEN_STATUS.items())
        status = list(result)[0][0]

        # Convert status codes back to human readable strings
        result = filter(lambda item: item[1] == self.flags,
                                 flags.TAC_PLUS_REPLY_FLAGS.items())
        reply_flags = list(result)[0][0]

        # Build the string representation
        fields = f'status: {status}, flags: {reply_flags},' \
                 f' server_msg: {self.server_msg}, data: {self.data}'

        return fields


class TACACSPlusAuthenReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication REPLY packet
    bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AuthenReplyFields(status=0x00, flags=0x00),
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

        # Initialise the packet body fields
        self._status = None
        self._flags = None
        self._server_msg_len = None
        self._server_msg = None
        self._data_len = None
        self._data = None

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dict doesn't contain these keys then we are decoding a REPLY
        # rather than building a REPLY packet
        try:
            self._status = fields.status
            self._flags = fields.flags
            self._server_msg = fields.server_msg
            self._server_msg_len = len(self._server_msg)
            self._data = fields.data
            self._data_len = len(self._data)
        except TypeError:
            raise

        # Build packet structure
        try:
            # B = unsigned char
            self._body = struct.pack('BB', self._status, self._flags)
            # !H = network-order (big-endian) unsigned short
            self._body += struct.pack('!HH', self._server_msg_len, self._data_len)

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
        packet = f'status: {self._status}, flags: {self._flags},' \
                 f' server_msg_len: {self._server_msg_len}, data_len:' \
                 f' {self._data_len}, server_msg: {self._server_msg},' \
                 f' data: {self._data}'

        return packet
