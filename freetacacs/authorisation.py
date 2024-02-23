"""
Module implements TACACS+ authorisation packets

Classes:
    TACACSPlusAuthorRequest
    TACACSPlusAuthorResponse

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


@dataclass
class AuthorRequestFields:
    """Defines Authorisation Request packet fields"""
    authen_method: int = 0x00
    priv_lvl: int = 0x00
    authen_type: int = 0x00
    authen_service: int = 0x00
    user: str = ''
    port: str = ''
    arg_cnt: int = 1
    remote_address: str = ''
    args: list = field(default_factory=list)


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

        self._validate_args()


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
          None
        Returns:
          None
        """

        validated_args = []

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

            validated_args.append(argument)

        # Assign validated args back to the args method
        self.args = validated_args


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
        for arg in self.args:
            fields += f', arg_{arg}'

        return fields


class TACACSPlusAuthorRequest(Packet):
    """Class to handle encoding/decoding of TACACS+ Authorisation REQUEST packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AuthorRequestFields(),
                 secret=None):
        """Initialise a TACACS+ Authorisation REQUEST packet body

        Initialise a TACACS+ Authorisation REQUEST packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: authen_method, priv_lvl,
        authen_type, authen_service, user, port, remote_address, arg_cnt. A
        args dict should be provided containing the arg N authorisation arguments.
        At the very least this dict MUST alwals contain a service argument.
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
        # |   user ...
        # +----------------+----------------+----------------+----------------+
        # |   port ...
        # +----------------+----------------+----------------+----------------+
        # |   rem_addr ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 1 ...
        # +----------------+----------------+----------------+----------------+
        # |   arg 2 ...
        # +----------------+----------------+----------------+----------------+
        # |   ...
        # +----------------+----------------+----------------+----------------+
        # |   arg N ...
        # +----------------+----------------+----------------+----------------+

        pass

