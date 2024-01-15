import six
import struct
import logging
from hashlib import md5

log = logging.getLogger(__name__)

class TACACSPlusPacket:
    """Base class to handle encoding/decoding TACACS+ packet bodies.

    All TACACS+ packet type(s) START, REPLY, CONTINUE etc inherit from here.
    """

    def __init__(self, header, body, secret=None):
        """Initialise a TACAS+ packet body

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
    def deobfuscate(self):
        """Deobfuscate the packet body

        Args:
          None
        Exceptions:
          None
        Returns:
          body(struct): deOfuscated packet body
        """

        return self.obfuscate


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

        packet_body = list()
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

