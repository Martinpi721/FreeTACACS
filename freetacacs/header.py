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
    """Defines TACACS+ header fields required to create packets"""
    version: int
    packet_type: int
    flags: str
    session_id: str


class TACACSPlusHeader:
    """Class to hand encoding/decoding the headers of TACACS+ packets"""

    def __init__(self, fields, sequence_no=1, flags=0):
        """Initialise the packet object

        Args:
          fields(dict): containing the following header fields (version,
                        packet_type, sequence_no, flags, session_id and length)
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

        self._version = fields['version']
        self._packet_type = fields['packet_type']
        self._sequence_no = sequence_no
        self._flags = flags
        self._session_id = fields['session_id']
        self._length = fields['length']

        # Build header structure
        try:
            self._header = struct.pack('BBBB', # B = unsigned char
                                       self._version,
                                       self._packet_type,
                                       self._sequence_no,
                                       self._flags)

            # !I = network-order (big-endian) unsigned int
            self._header += struct.pack('!I', self._session_id)
            self._header += struct.pack('!I', self._length)
        except struct.error as e:
            raise struct.error('All TACACS+ header fields must be integers') from e


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
          fields(dict): containing header field name/value pairs
        """

        fields = {}

        try:
            raw = six.BytesIO(encoded_header)
            raw_chars = raw.read(4)
        except TypeError as e:
            raise ValueError('Unable to extract header. Not encoded as a' \
                             ' byte-like object') from e

        try:
            (fields['version'],
            fields['packet_type'],
            fields['sequence_no'],
            fields['flags']) = struct.unpack('BBBB', # B = unsigned char
                                             raw_chars)

            # !I = network-order (big-endian) unsigned int
            fields['session_id'], fields['length'] = struct.unpack('!II', raw.read(8))
        except struct.error as e:
            raise ValueError('Unable to extract header. TACACS+ client/server' \
                             ' shared key probably does not match') from e

        return fields


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
