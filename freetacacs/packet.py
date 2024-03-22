"""
Module implements the base TACACS+ packet class

Classes:
    TACACSPlusPacket
    RequestFields
    ReplyFields

Functions:
    None
"""

import struct
import logging
from hashlib import md5
from dataclasses import dataclass
from twisted.logger import Logger
import six
import re

# Local imports
from freetacacs import flags
from freetacacs.exceptions import (MissingServiceArgument,
                                   MissingCmdArgument,
                                   InvalidChapVersion,
                                   InvalidPppPeerId)

# Setup the logger
log = Logger()


@dataclass
class BaseFields:
    """Defines base packet fields validator.

    Used as a base class only. This is never used directly to create
    a instance. Use the relevant AuthenStart/AuthorRequest/AccountRequest
    class instead.
    """

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
class RequestFields(BaseFields):
    """Defines base Start/Request packet fields.

    Used as a base class only. This is never used directly to create
    a instance. Use the relevant AuthenStart/AuthorRequest/AccountRequest
    class instead.
    """

    priv_lvl: int = 0x00
    authen_type: int = 0x00
    authen_service: int = 0x00
    user: str = ''
    port: str = ''
    remote_address: str = ''

    # Validate the data
    def __post_init__(self):
        if not isinstance(self.priv_lvl, int):
            raise TypeError('Privilege Level should be of type int')

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


@dataclass
class ReplyFields(BaseFields):
    """Defines base Reply packet fields.

    Used as a base class only. This is never used directly to create
    a instance. Use the relevant AuthenReply/AuthorReply/AccountReply
    class instead.
    """

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

        if not isinstance(self.server_msg, str):
            raise TypeError('Server Message should be of type string')

        if not isinstance(self.data, str):
            raise TypeError('Data should be of type string')



class TACACSPlusPacket:
    """Base class to handle encoding/decoding TACACS+ packet bodies.

    All TACACS+ packet type(s) START, REPLY, CONTINUE etc inherit from here.
    """

    def __init__(self, header, body, secret=None):
        """Initialise a TACACS+ packet body

        Args:
          header(obj): instance of a TACACSPlusHeader class
          body(bytes): byte encoded TACACS+ packet body
          secret(str): client/server shared secret
        Exceptions:
          None
        Returns:
          None
        """
        self._header = header
        self._body = body
        self._secret = secret


    @property
    def length(self):
        """Return the length of the packet body

        Args:
          None
        Exceptions:
          None
        Returns:
          length(int): length of packet body
        """

        return len(self._body)


    @property
    def deobfuscate(self):
        """Deobfuscate the packet body

        Args:
          None
        Exceptions:
          None
        Returns:
          body(struct): deofuscated packet body
        """

        return self.obfuscate


    @property
    def chap(self, password, version='CHAP'):
        """Build chap authentication string add it to the packet data attribute

        Args:
          password(str): Users password
          version(str): CHAP authentication version [CHAP|MSCHAPv1|MSCHAPv2]
        Exceptions:
          InvalidChapVersion
          InvalidPppPeerId
        Returns:
          chap_ppp_id(int): chap ppp peer id
          chap_challenge(str): chap challenge secret
          chap_response(byte): md5 hash of ppp peer id, password and chap
                               challenge secret
        """

        # Default chap response length
        CHAP_RESPONSE_LENGTH = flags.CHAP_CHALLENGE_RESPONSE_LENGTH

        # Override with Microsoft CHAP response length or fail
        if version in ['MSCHAPv1', 'MSCHAPv2']:
            CHAP_RESPONSE_LENGTH = flags.MSCHAP_CHALLENGE_RESPONSE_LENGTH
        else:
            raise InvalidChapVersion(f'{version} is not a valid CHAP version')

        challenge_len = len(self._data) - CHAP_RESPONSE_LENGTH

        # Extract chap challenge from data field
        chap_ppp_id = chr(self._data[0])
        chap_challenge = self._data[1:challenge_len].decode('UTF-8')
        chap_response = self._data[challenge_len:]

        return chap_ppp_id, chap_challenge, chap_response


    @chap.setter
    def chap(self, password, chap_ppp_id, chap_challenge):

        err_msg = f'{chap_ppp_id} is not a valid PPP Peer Id. PPP Peer Ids' \
                   ' must be integers in the range of 0 to 255'

        if not isinstance(chap_ppp_id, int):
            raise InvalidPppPeerId(err_msg)

        if chap_ppp_id < 0 or chap_ppp_id > 255:
            raise InvalidPppPeerId(err_msg)

        self._data = six.b(chap_ppp_id) + six.b(chap_challenge)
        self._data += md5(six.b(chap_ppp_id + password + chap_challenge)).digest()


    @property
    def obfuscate(self):
        """Obfuscate the packet body

        Args:
          None
        Exceptions:
          None
        Returns:
          obfuscated_body(struct): Obfuscated packet body
        """

        packet_body = []
        body_length = len(self._body)

        # Generate the MD5 hash from header fields and shared secret
        hash_input = struct.pack('!I', self._header.session_id)
        hash_input += six.b(self._secret)
        hash_input += struct.pack('B', self._header.version)
        hash_input += struct.pack('B', self._header.sequence_no)

        # Generate the first MD5 hash
        pseudo_pad = hashed = md5(hash_input).digest()

        # Generate subsequent MD5 hashes and concatenate
        while len(pseudo_pad) < body_length:
            hashed = md5(hash_input + hashed).digest()
            pseudo_pad += hashed

        # Trim pseudo_pad length to length of packet body
        pseudo_pad = pseudo_pad[0:(body_length)]
        pseudo_pad = list(struct.unpack('B' * len(pseudo_pad), pseudo_pad))

        # Unpack the body structure and XOR each byte with pseudo_pseudo_pad
        for x in struct.unpack('B' * body_length, self._body):
            packet_body.append(x ^ pseudo_pad.pop(0))

        obfuscated_body = struct.pack('B' * len(packet_body), *packet_body)

        return obfuscated_body


    def __bytes__(self):
        """Byte representation of TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          packet(byte): containing the TACACS+ packet header/body
        """

        return self._header.encoded + self.obfuscate
