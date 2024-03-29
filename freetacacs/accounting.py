"""
Module implements TACACS+ accoutning packets

Classes:
    TACACSPlusAccountRequest
    TACACSPlusAccountReply
    AcctRequestFields

Functions:
    None
"""

import struct
import logging
from dataclasses import dataclass, field
from twisted.logger import Logger
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet
from freetacacs.packet import RequestFields, ReplyFields

# Setup the logger
log = Logger()


@dataclass
class AcctRequestFields(RequestFields):
    """Defines Accounting Request packet fields."""

    flags: int = 0x02
    authen_method: int = 0x00
    arg_cnt: int = 1
    args: list = field(default_factory=list)


    # Validate the data
    def __post_init__(self):
        # Extend our parent class __post_init__ method
        super().__post_init__()

        if not isinstance(self.flags, int):
            raise TypeError('Flags should be of type int')

        if not isinstance(self.authen_method, int):
            raise TypeError('Authentication method should be of type int')

        if not isinstance(self.arg_cnt, int):
            raise TypeError('Argument Count should be of type int')

        if not isinstance(self.args, list):
            raise TypeError('Arguments should be of type list')

        # Validate args if we have some
        if len(self.args) > 0:
            self._validate_args()


    def __str__(self):
        """String representation of the accounting request fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the accounting request fields
        """

        # Convert privelege level flag codes back to human readable strings
        result = filter(lambda item: item[1] == self.flags,
                                     flags.TAC_PLUS_ACCT_FLAGS.items())
        request_flags = list(result)[0][0]

        # Convert authentication method flag codes back to human readable
        # strings
        result = filter(lambda item: item[1] == self.authen_method,
                                     flags.TAC_PLUS_AUTHEN_METHODS.items())
        authen_method = list(result)[0][0]

        # Convert privelege level flag codes back to human readable strings
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
        fields = f'flags: {request_flags}, authen_method: {authen_method},' \
                 f' priv_lvl: {priv_lvl}, authen_type: {authen_type},' \
                 f' authen_service: {authen_service}, user: {self.user},' \
                 f' port: {self.port}, arg_cnt: {self.arg_cnt},' \
                 f' remote_address: {self.remote_address}'

        # Add the args to the string
        count = 1
        for arg in self.args:
            fields += f', arg_{count}: {arg}'
            count += 1

        return fields


class TACACSPlusAccountRequest(Packet):
    """Class to handle encoding/decoding of TACACS+ Accounting REQUEST packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AcctRequestFields(), secret=None):
        """Initialise a TACACS+ Accounting REQUEST packet body

        Initialise a TACACS+ Aaccounting REQUEST packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dataclass must contain the following attributes: flags,
        authen_method, priv_lvl, authen_type, authen_service, user, port,
        remote_address, arg_cnt. A args list should be provided containing the
        arg N authorisation arguments. At the very least this list MUST always
        contain a service argument. See RFC8907 for details on contents of
        each field and authorisation
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
        #
        # +----------------+----------------+----------------+----------------+
        # |      flags     |  authen_method |    priv_lvl    |  authen_type   |
        # +----------------+----------------+----------------+----------------+
        # | authen_service |    user_len    |    port_len    |  rem_addr_len  |
        # +----------------+----------------+----------------+----------------+
        # |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
        # +----------------+----------------+----------------+----------------+
        # |   arg_N_len    |    user ...                                      |
        # +----------------+----------------+----------------+----------------+
        # |   port ...                                                        |
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...                                                    |
        # +----------------+----------------+----------------+----------------+
        # |   arg_1 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   arg_2 ...                                                       |
        # +----------------+----------------+----------------+----------------+
        # |   ...                                                             |
        # +----------------+----------------+----------------+----------------+
        # |   arg_N ...                                                       |
        # +----------------+----------------+----------------+----------------+

        # Extend our parent class __init__ method
        super().__init__(header, body, secret)

        # Initialise the packet body fields
        self._flags = None
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

        # If fields dataclass doesn't contain these keys then we are decoding a Request
        # rather than building a Request packet
        try:
            self._flags = fields.flags
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

        # Build packet structure
        try:
            # B = unsigned char
            self._body = struct.pack('BBBB', self._flags, self._authen_method,
                                     self._priv_lvl, self._authen_type)

            # B = unsigned char
            self._body += struct.pack('BBBBB', self._authen_service, self._user_len,
                                      self._port_len, self._rem_addr_len, self._arg_cnt)

            # Pack the argument lengths
            for arg_len in self._args_len:
                self._body += struct.pack('B', arg_len)

            # Byte encode
            user = six.b(self._user)
            port = six.b(self._port)
            remote_address = six.b(self._remote_address)

            # s = char[]
            for value in (user, port, remote_address):
                self._body += struct.pack(f'{len(value)}s', value)

            # Byte encode and pack the arguments
            # s = char[]
            for arg in self._args:
                value = six.b(arg)
                self._body += struct.pack(f'{len(value)}s', value)
        except struct.error as e:
            raise ValueError('Unable to encode AcctRequest packet. Required' \
                             ' status must an interger.') from e
        except TypeError as e:
            raise ValueError('Unable to encode AcctRequest packet. Required' \
                             ' arguments server_msg and data' \
                             ' must be strings.') from e

        # Set the packet body length in the header
        self._header.length = len(self._body)


    @property
    def decode(self):
        """Decode a TACAS+ Accounting request packet body

        Args:
          None
        Exceptions:
          ValueError
        Returns:
          fields(obj): instance of AcctRequestFields dataclass
        """

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            # B = unsigned char
            (self._flags,
             self._authen_method,
             self._priv_lvl,
             self._authen_type,
             self._authen_service) = struct.unpack('BBBBB', body.read(5))

            (self._user_len,
             self._port_len,
             self._rem_addr_len,
             self._arg_cnt) = struct.unpack('BBBB', body.read(4))

            # Unpack the length of each argument
            for x in range(0, self._arg_cnt):
                self._args_len.append(struct.unpack('B', body.read(1))[0])

            # Byte decode
            self._user = body.read(self._user_len).decode('UTF-8')
            self._port = body.read(self._port_len).decode('UTF-8')
            self._remote_address = body.read(self._rem_addr_len).decode('UTF-8')

            # Unpack each of the arguments
            for arg_len in self._args_len:
                self._args.append(body.read(arg_len).decode('UTF-8'))
        except (struct.error, ValueError) as e:
            raise ValueError('Unable to decode AcctRequest packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        fields = AcctRequestFields(authen_method=self._authen_method,
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
        packet = f'flags: {self._flags}, authen_method: {self._authen_method},' \
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
class AcctReplyFields(ReplyFields):
    """Defines Accounting Reply packet fields."""

    status: int = 0x01

    def __str__(self):
        """String representation of the accounting rely fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the accounting reply fields
        """

        # Convert status codes back to human readable strings
        result = filter(lambda item: item[1] == self.status,
                                     flags.TAC_PLUS_ACCT_STATUS.items())
        status = list(result)[0][0]

        # Build the string representation
        fields = f'status: {status}, server_msg: {self.server_msg},' \
                 f' data: {self.data}'

        return fields


class TACACSPlusAccountReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Accounting REPLY packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AcctReplyFields(), secret=None):
        """Initialise a TACACS+ Accounting REPLY packet body

        Initialise a TACACS+ Aaccounting REPLY packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dataclass must contain the following attributes: server_msg, status
        and data

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
        #
        # +----------------+----------------+----------------+----------------+
        # |         server_msg len          |            data_len             |
        # +----------------+----------------+----------------+----------------+
        # |     status     |         server_msg ...                           |
        # +----------------+----------------+----------------+----------------+
        # |     data ...                                                      |
        # +----------------+----------------+----------------+----------------+

        # Extend our parent class __init__ method
        super().__init__(header, body, secret)

        # Initialise the packet body fields
        self._server_msg_len = None
        self._data_len = None
        self._status = None
        self._server_msg = None
        self._data = None

        # If body is not empty nothing more is required from __init__
        if len(self._body) > 0:
            return None

        # If fields dataclass doesn't contain these keys then we are decoding a Reply
        # rather than building a Reply packet
        try:
            self._status = fields.status
            self._server_msg = fields.server_msg
            self._server_msg_len = len(self._server_msg)
            self._data = fields.data
            self._data_len = len(self._data)
        except TypeError:
            raise

        # Build packet structure
        try:
            # !H = network-order (big-endian) unsigned short
            self._body = struct.pack('!HH', self._server_msg_len, self._data_len)

            # B = unsigned char
            self._body += struct.pack('B', self._status)

            # Byte encode
            server_msg = six.b(self._server_msg)
            data = six.b(self._data)

            # s = char[]
            for value in (server_msg, data):
                self._body += struct.pack(f'{len(value)}s', value)

        except struct.error as e:
            raise ValueError('Unable to encode AcctReply packet. Required' \
                             ' status must an interger.') from e
        except TypeError as e:
            raise ValueError('Unable to encode AcctReply packet. Required' \
                             ' arguments server_msg and data' \
                             ' must be strings.') from e

        # Set the packet body length in the header
        self._header.length = len(self._body)

        return None


    @property
    def decode(self):
        """Decode a TACAS+ Accounting reply packet body

        Args:
          None
        Exceptions:
          ValueError
        Returns:
          fields(obj): instance of AcctReplyFields dataclass
        """

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret is not None:
            body = six.BytesIO(self.deobfuscate)
        else:
            body = raw

        # Decode the packet body
        try:
            # !H = network-order (big-endian) unsigned short
            self._server_msg_len, self._data_len = struct.unpack('!HH', body.read(4))

            # B = unsigned char
            self._status = struct.unpack('B', body.read(1))[0]

            # Byte decode
            self._server_msg = body.read(self._server_msg_len).decode('UTF-8')
            self._data = body.read(self._data_len).decode('UTF-8')
        except (struct.error, ValueError) as e:
            raise ValueError('Unable to decode AcctReply packet. TACACS+' \
                             ' client/server shared key probably does not' \
                             ' match') from e

        fields = AcctReplyFields(status=self._status, server_msg=self._server_msg,
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
        packet = f'server_msg_len: {self._server_msg_len},' \
                 f' data_len: {self._data_len}, status: {self._status},' \
                 f' server_msg: {self._server_msg}, data: {self._data}'

        return packet
