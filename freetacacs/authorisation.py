"""
Module implements TACACS+ authorisation packets

Classes:
    AuthorFields
    AuthorRequestFields
    AuthorReplyFields
    TACACSPlusAuthorRequest
    TACACSPlusAuthorResponse
    MissingServiceArgument
    MissingCmdArgument

Functions:
    None
"""

import re
import struct
from dataclasses import dataclass, field
from twisted.logger import Logger
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet

# Setup the logger
log = Logger()


class MissingServiceArgument(Exception):
    """Raised when authorisation args do not include a service argument"""


class MissingCmdArgument(Exception):
    """Raised when authorisation arg service=shell but no cmd provided"""


@dataclass
class AuthorFields:
    """Defines base Authorisation packet fields"""

    arg_cnt: int = 1
    args: list = field(default_factory=list)


    def _validate_args(self):
        """Validate the authorisation arguments

        The authorization arguments in both the REQUEST and the REPLY are
        argument-value pairs. The argument and the value are in a single string
        and are separated by either a "=" (0X3D) or a "*" (0X2A). The equals
        sign indicates a mandatory argument. The asterisk indicates an optional
        one. The value part of an argument-value pair may be empty, that is,
        the length of the value may be zero.

        Though the arguments allow extensibility, a common core set of
        authorization arguments be supported by clients and servers;
        See RFC8907 for details on contents of each field and authorisation
        arguments.

        Args:
          None
        Exceptions:
          MissingServiceArgument
        Returns:
          None
        """

        validated_args = []
        service_included = False
        cmd_included = False
        cmd_required = False

        # Loop over the arguments and validate
        for argument in self.args:
            # Check that we have a argument name
            if argument.startswith('=') or argument.startswith('*'):
                log.warn(text=f'Ignoring invalid authorisation argument' \
                              f' should not start with either [=*]')
                continue

            # Split out the argument from the value
            seperator = re.findall(r'[=*]', argument)
            try:
                args = argument.split(seperator[0], 1)
            except IndexError as e:
                log.warn(text=f'Ignoring invalid authorisation argument'
                              f' [{argument}]. No seperator.')
                continue

            if args[0] == 'service':
                service_included = True
                if args[1] == 'shell':
                    cmd_required = True

            if args[0] == 'cmd':
                cmd_included = True

            validated_args.append(argument)

        # A service argument must always be provided
        if not service_included:
            raise MissingServiceArgument('Arguments must contain a service')

        # If service=shell then the cmd argument must exist
        if cmd_required and not cmd_included:
            raise MissingCmdArgument('When service=shell then cmd argument is required')

        # Assign validated args back to the args method
        self.args = validated_args


@dataclass
class AuthorRequestFields(AuthorFields):
    """Defines Authorisation Request packet fields"""

    authen_method: int = 0x00
    priv_lvl: int = 0x00
    authen_type: int = 0x00
    authen_service: int = 0x00
    user: str = ''
    port: str = ''
    remote_address: str = ''


    # Validate the data
    def __post_init__(self):
        """Validate the authorisation request fields

        Args:
          None
        Exceptions:
          TypeError
        Returns:
          None
        """

        if not isinstance(self.authen_method, int):
            raise TypeError('Authentication Method should be of type int')

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

        if not isinstance(self.arg_cnt, int):
            raise TypeError('Argument Count should be of type int')

        if not isinstance(self.args, list):
            raise TypeError('Arguments should be of type list')

        # Validate args if we have some
        if len(self.args) > 0:
            self._validate_args()


    def __str__(self):
        """String representation of the authorisation request fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the authorisation request fields
        """

        # Convert priveledge level flag codes back to human readable strings
        result = filter(lambda item: item[1] == self.priv_lvl,
                                     flags.TAC_PLUS_PRIV_LVL.items())
        priv_lvl = list(result)[0][0]

        # Convert authentication type flag codes back to human readable
        # strings
        result = filter(lambda item: item[1] == self.authen_method,
                                     flags.TAC_PLUS_AUTHEN_METHODS.items())
        authen_method = list(result)[0][0]

        # Convert authentication service flag codes back to
        # human readable strings
        result = filter(lambda item: item[1] == self.authen_service,
                                     flags.TAC_PLUS_AUTHEN_SVC.items())
        authen_service = list(result)[0][0]

        # Build the string representation
        fields = f'priv_lvl: {priv_lvl}, authen_method: {authen_method},' \
                 f' authen_service: {authen_service}, user: {self.user},' \
                 f' port: {self.port}, arg_cnt: {self.arg_cnt},' \
                 f' remote_address: {self.remote_address}'

        # Add the args to the string
        count = 1
        for arg in self.args:
            fields += f', arg_{count}: {arg}'
            count += 1

        return fields


class TACACSPlusAuthorRequest(Packet):
    """Class to handle encoding/decoding of TACACS+ Authorisation REQUEST packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AuthorRequestFields(), secret=None):
        """Initialise a TACACS+ Authorisation REQUEST packet body

        Initialise a TACACS+ Authorisation REQUEST packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: authen_method, priv_lvl,
        authen_type, authen_service, user, port, remote_address, arg_cnt. A
        args list should be provided containing the arg N authorisation arguments.
        At the very least this list MUST always contain a service argument.
        See RFC8907 for details on contents of each field and authorisation
        arguments.

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

        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |  authen_method |    priv_lvl    |  authen_type   | authen_service |
        # +----------------+----------------+----------------+----------------+
        # |    user len    |    port len    |  rem_addr len  |    arg_cnt     |
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 len    |   arg 2 len    |      ...       |   arg N len    |
        # +----------------+----------------+----------------+----------------+
        # |   user ...                                                        |
        # +----------------+----------------+----------------+----------------+
        # |   port ...                                                        |
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...                                                    |
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   arg 2 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   ...                                                             |
        # +----------------+----------------+----------------+----------------+
        # |   arg N ...                                                       |
        # +----------------+----------------+----------------+----------------+

        # Extend our parent class __init__ method
        super().__init__(header, body, secret)

        # Initialise the packet body fields
        self._authen_method = None
        self._priv_lvl = None
        self._authen_type = None
        self._authen_service = None
        self._user_len = None
        self._port_len = None
        self._rem_addr_len = None
        self._arg_cnt = None
        self._user = None
        self._port = None
        self._remote_address = None
        self._args_len = []
        self._args = []

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dict doesn't contain these keys then we are decoding a Request
        # rather than building a Request packet
        try:
            self._authen_method = fields.authen_method
            self._priv_lvl = fields.priv_lvl
            self._authen_type = fields.authen_type
            self._authen_service = fields.authen_service
            self._user = fields.user
            self._user_len = len(self._user)
            self._port = fields.port
            self._port_len = len(self._port)
            self._remote_address = fields.remote_address
            self._rem_addr_len = len(self._remote_address)
            self._args = fields.args
            self._arg_cnt = len(self._args)

            for arg in self._args:
                self._args_len.append(len(arg))
        except TypeError:
            raise


    @property
    def decode(self):
        """Decode a TACAS+ Authorisation request packet body

        Args:
          None
        Exceptions:
          ValueError
        Returns:
          fields(obj): instance of AuthorRequestFields dataclass
        """

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            self._authen_method, self._priv_lvl = struct.unpack('BB', body.read(2))
            self._authen_type, self._authen_service = struct.unpack('BB', body.read(2))

            (self._user_len,
             self._port_len,
             self._rem_addr_len,
             self._arg_cnt) = struct.unpack('BBBB', body.read(4))

            # Unpack the length of each argument
            for x in range(0, self._arg_cnt):
                self._args_len.append(struct.unpack('B', body.read(1))[0])

            self._user = body.read(self._user_len).decode('UTF-8')
            self._port = body.read(self._port_len).decode('UTF-8')
            self._remote_address = body.read(self._rem_addr_len).decode('UTF-8')

            # Unpack each of the arguments
            for arg_len in self._args_len:
                self._args.append(body.read(arg_len).decode('UTF-8'))
        except (struct.error, ValueError) as e:
            raise ValueError('Unable to decode AuthorRequest packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        fields = AuthorRequestFields(authen_method=self._authen_method,
                                     priv_lvl=self._priv_lvl,
                                     authen_type=self._authen_type,
                                     authen_service=self._authen_service,
                                     user=self._user,
                                     port=self._port,
                                     remote_address=self._remote_address,
                                     arg_cnt=self._arg_cnt,
                                     args=self._args)

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
        packet = f'authen_method: {self._authen_method},' \
                 f' priv_lvl: {self._priv_lvl},' \
                 f' authen_type: {self._authen_type},' \
                 f' authen_service: {self._authen_service},' \
                 f' user_len: {self._user_len}, port_len: {self._port_len},' \
                 f' rem_addr_len: {self._rem_addr_len},' \
                 f' arg_cnt: {self._arg_cnt}'

        # Add the argument lengths
        count = 1
        for arg_len in self._args_len:
            packet += f', arg_{count}_len: {arg_len}'
            count += 1

        # Add the user/port and remote address
        packet += f', user: {self._user}, port: {self._port}' \
                  f', rem_addr: {self._remote_address}'

        # Add the argument values
        count = 1
        for arg in self._args:
            packet += f', arg_{count}: {arg}'
            count += 1

        return packet


@dataclass
class AuthorReplyFields(AuthorFields):
    """Defines Authorisation Reply packet fields"""

    status: int = 0x00
    server_msg: str = ''
    data: str = ''


    # Validate the data
    def __post_init__(self):
        """Validate the authorisation request fields

        Args:
          None
        Exceptions:
          TypeError
        Returns:
          None
        """

        if not isinstance(self.status, int):
            raise TypeError('Status should be of type int')

        if not isinstance(self.arg_cnt, int):
            raise TypeError('Argument Count should be of type int')

        if not isinstance(self.server_msg, str):
            raise TypeError('Server Message should be of type string')

        if not isinstance(self.data, str):
            raise TypeError('Data should be of type string')

        if not isinstance(self.args, list):
            raise TypeError('Arguments should be of type list')

        # Validate args if we have some
        if len(self.args) > 0:
            self._validate_args()


    def __str__(self):
        """String representation of the authorisation reply fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the authorisation reply fields
        """

        # Convert the status flag codes back to human readable strings
        result = filter(lambda item: item[1] == self.status,
                                     flags.TAC_PLUS_AUTHOR_STATUS.items())
        status = list(result)[0][0]

        # Build the string representation
        fields = f'status: {status}, arg_cnt: {self.arg_cnt},' \
                 f' server_msg: {self.server_msg},' \
                 f' data: {self.data}'

        # Add the args to the string
        count = 1
        for arg in self.args:
            fields += f', arg_{count}: {arg}'
            count += 1

        return fields


class TACACSPlusAuthorReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Authorisation REPLY packet bodies"""


    def __init__(self, header, body=six.b(''),
                 fields=AuthorReplyFields(), secret=None):
        """Initialise a TACACS+ Authorisation REPLY packet body

        Initialise a TACACS+ Authorisation REPLY packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: status, arg_cnt, server_msg,
        data. A args list should be provided containing the arg N authorisation arguments.
        At the very least this list MUST always contain a service argument.
        See RFC8907 for details on contents of each field and authorisation
        arguments.

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

        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        # +----------------+----------------+----------------+----------------+
        # |    status      |     arg_cnt    |         server_msg len          |
        # +----------------+----------------+----------------+----------------+
        # +            data len             |    arg 1 len   |    arg 2 len   |
        # +----------------+----------------+----------------+----------------+
        # |      ...       |   arg N len    |         server_msg ...          |
        # +----------------+----------------+----------------+----------------+
        # |   data ...                                                        |
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   arg 2 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   ...                                                             |
        # +----------------+----------------+----------------+----------------+
        # |   arg N ...                                                       |
        # +----------------+----------------+----------------+----------------+

        # Extend our parent class __init__ method
        super().__init__(header, body, secret)

        # Initialise the packet body fields
        self._status = None
        self._arg_cnt = None
        self._server_msg = None
        self._data = None
        self._args_len = []
        self._args = []

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dict doesn't contain these keys then we are decoding a Reply
        # rather than building a Reply packet
        try:
            self._status = fields.status
            self._server_msg_len = len(fields.server_msg)
            self._data_len = len(fields.data)
            self._server_msg = fields.server_msg
            self._data = fields.data
            self._args = fields.args
            self._arg_cnt = len(self._args)

            for arg in self._args:
                self._args_len.append(len(arg))
        except TypeError:
            raise

        # Build packet structure
        try:
            # B = unsigned char
            self._body = struct.pack('BB', self._status, self._arg_cnt)
            # !H = network-order (big-endian) unsigned short
            self._body += struct.pack('!HH', self._server_msg_len, self._data_len)

            # Pack the argument lengths
            for arg_len in self._args_len:
                self._body += struct.pack('B', arg_len)

            # Byte encode
            server_msg = six.b(self._server_msg)
            data = six.b(self._data)

            # s = char[]
            for value in (server_msg, data):
                self._body += struct.pack(f'{len(value)}s', value)

            # Byte encode and pack the arguments
            # s = char[]
            for arg in self._args:
                value = six.b(arg)
                self._body += struct.pack(f'{len(value)}s', value)

        except struct.error as e:
            raise ValueError('Unable to encode AuthorReply packet. Required' \
                             ' arguments status, arg_cnt must be intergers.' \
                             ) from e
        except TypeError as e:
            raise ValueError('Unable to encode AuthorReply packet. Required' \
                             ' arguments server_msg and data' \
                             ' must be strings. args must be a list of strings' \
                             ) from e

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
        packet = f'status: {self._status}, arg_cnt: {self._arg_cnt},' \
                 f' server_msg_len: {self._server_msg_len},' \
                 f' data_len: {self._data_len}'

        # Add the argument lengths
        count = 1
        for arg_len in self._args_len:
            packet += f', arg_{count}_len: {arg_len}'
            count += 1

        packet += f', server_msg: {self._server_msg}, data: {self._data}'

        # Add the argument values
        count = 1
        for arg in self._args:
            packet += f', arg_{count}: {arg}'
            count += 1

        return packet
