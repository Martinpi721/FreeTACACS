"""
Module implements the TACACS+ header class

Classes:
    TACACSPlusHeader

Functions:
    None
"""

import struct
import logging
from dataclasses import dataclass
import six

# Local imports
from freetacacs.flags import TAC_PLUS_PACKET_TYPES

log = logging.getLogger(__name__)

@dataclass
class HeaderFields:
    """TACACS+ header fields required to create packets"""
    version: int
    packet_type: int
    session_id: int
    length: int = 0
    sequence_no: int = 1
    flags: int = 0

    # Validate the data
    def __post_init__(self):
        if not isinstance(self.version, int):
            raise TypeError('Version should be of type int')

        if not isinstance(self.packet_type, int):
            raise TypeError('Packet Type should be of type int')

        if not isinstance(self.session_id, int):
            raise TypeError('Session Id should be of type int')

        if not isinstance(self.length, int):
            raise TypeError('Length should be of type int')

        if not isinstance(self.sequence_no, int):
            raise TypeError('Sequence No should be of type int')

        if not isinstance(self.flags, int):
            raise TypeError('Flags should be of type int')


    def __str__(self):
        """String representation of the header fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the header fields
        """

        # Map the hex packet type to a text string
        result = filter(lambda item: item[1] == self.packet_type,
                                     TAC_PLUS_PACKET_TYPES.items())

        # There will only ever be one result so take first tuple value from it
        packet_type = list(result)[0][0]

        return f'version: {self.version}, packet_type: {packet_type},' \
               f' session_id: {self.session_id}, length: {self.length},' \
               f' sequence_no: {self.sequence_no}, flags: {self.flags}'


class TACACSPlusHeader:
    """Class to hand encoding/decoding the headers of TACACS+ packets"""

    def __init__(self, fields, sequence_no=1, flags=0):
        """Initialise the packet object

        Args:
          fields(obj): instance of HeaderFields dataclass
          sequence_no(int): containing the packet sequence number
          flags(int): containing the TACACS+ flags
        Exceptions:
          PacketAttributeNotSet
        Returns:
          None
        """

        # All TACACS+ packets always begin with the following 12 byte header.
        # The header is always cleartext and describes the remainder of the
        # packet:
        # 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |major  | minor  |                |                |                |
        # |version| version|      type      |     seq_no     |   flags        |
        # +----------------+----------------+----------------+----------------+
        # |                            session_id                             |
        # +----------------+----------------+----------------+----------------+
        # |                              length                               |
        # +----------------+----------------+----------------+----------------+

        self._version = fields.version
        self._packet_type = fields.packet_type
        self._sequence_no = sequence_no
        self._flags = flags
        self._session_id = fields.session_id
        self._length = fields.length
        self._header = b''


    @property
    def length(self):
        """All the body lentgh to TACACS+ packet header

        Args:
          length(int): length of the TACACS+ body
        Exceptions:
          None
        Returns:
          length(int): length of the TACACS+ body
        """

        return self._length


    @length.setter
    def length(self, length):
        self._length = length


    @property
    def sequence_no(self):
        """Return the sequence no from a TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          sequence_no(int): containing the sequence no
        """

        return self._sequence_no


    @property
    def version(self):
        """Return the protocol version from a TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          version(int): containing the protocol version
        """

        return self._version


    @property
    def session_id(self):
        """Return the session id from a TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          session_id(int): containing the session id
        """

        return self._session_id


    @property
    def encoded(self):
        """Return a encoded TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          header(struct): packed packet header structure
        """

        # Build header structure
        self._header = struct.pack('BBBB', # B = unsigned char
                                   self._version,
                                   self._packet_type,
                                   self._sequence_no,
                                   self._flags)

        # !I = network-order (big-endian) unsigned int
        self._header += struct.pack('!I', self._session_id)
        self._header += struct.pack('!I', self._length)

        return self._header


    @property
    def packet_type(self):
        """Return the packet type from a TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          packet_type(str): containing TAC_PLUS_AUTHEN, TAC_PLUS_AUTHOR or
                            TAC_PLUS_ACCT
        """

        result = filter(lambda item: item[1] == self._packet_type,
                                     TAC_PLUS_PACKET_TYPES.items())
        return list(result)[0][0]


    @classmethod
    def decode(cls, encoded_header):
        """Decode a TACAS+ packet header

        Args:
          encoded_header(struct): containing header field values
        Exceptions:
          ValueError
        Returns:
          header(obj): instance of HeaderFields dataclass
        """

        try:
            raw = six.BytesIO(encoded_header)
            raw_chars = raw.read(4)
        except TypeError as e:
            raise ValueError('Unable to extract header. Not encoded as a' \
                             ' byte-like object') from e

        try:
            (version,
            packet_type,
            sequence_no,
            flags) = struct.unpack('BBBB', # B = unsigned char
                                   raw_chars)

            # !I = network-order (big-endian) unsigned int
            session_id, length = struct.unpack('!II', raw.read(8))

        except struct.error as e:
            raise ValueError('Unable to extract header.' \
                             ' Header does meet TACACS+ encoding standards.') from e

        return HeaderFields(version, packet_type, session_id, length,
                            sequence_no, flags)


    def __str__(self):
        """String representation of TACACS+ packet header

        Args:
          None
        Exceptions:
          None
        Returns:
          packet(str): containing the TACACS+ packet header/body
        """

        # Map the hex packet type to a text string
        result = filter(lambda item: item[1] == self._packet_type,
                                     TAC_PLUS_PACKET_TYPES.items())

        # There will only ever be one result so take first tuple value from it
        packet_type = list(result)[0][0]

        # Build the string representation
        packet = f'version: {self._version}, type: {packet_type},' \
                 f' session_id: {self._session_id}, length: {self._length},' \
                 f' sequence_no: {self._sequence_no}, flags: {self._flags}'

        return packet
