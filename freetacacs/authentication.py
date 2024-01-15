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
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet

log = logging.getLogger(__name__)

class TACACSPlusAuthenStart(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication START packet bodies"""

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
        fields['action'], fields['priv_lvl'] = struct.unpack('BB', body.read(2))
        fields['authen_type'], fields['service'] = struct.unpack('BB', body.read(2))
        user_len, port_len, rem_addr_len, data_len = struct.unpack('BBBB', body.read(4))
        fields['user'] = body.read(user_len)
        fields['port'] = body.read(port_len)
        fields['remote_address'] = body.read(rem_addr_len)
        fields['data'] = body.read(data_len)

        # Convert authentication action flag codes back to human readable strings
        result = filter(lambda item: item[1] == fields['action'],
                                     flags.TAC_PLUS_AUTHEN_ACTIONS.items())
        try:
            fields['action'] = list(result)[0][0]

            # Convert priveledge level flag codes back to human readable strings
            result = filter(lambda item: item[1] == fields['priv_lvl'],
                                         flags.TAC_PLUS_PRIV_LVL.items())
            fields['priv_lvl'] = list(result)[0][0]

            # Convert authentication type flag codes back to human readable strings
            result = filter(lambda item: item[1] == fields['authen_type'],
                                         flags.TAC_PLUS_AUTHEN_TYPES.items())
            fields['authen_type'] = list(result)[0][0]

            # Convert authentication service flag codes back to human readable strings
            result = filter(lambda item: item[1] == fields['service'],
                                         flags.TAC_PLUS_AUTHEN_SVC.items())
            fields['service'] = list(result)[0][0]
        except IndexError as e:
            raise ValueError('Unable to decode AuthenSTART packet. TACACS+ client/server' \
                             ' shared key probably does not match') from e

        return fields


class TACACSPlusAuthenReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Authentication REPLY packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields={'status': 0,
                         'flags': 0,
                         'server_msg': '',
                         'data': ''}, secret=None):
        """Initialise a TACAS+ Authentication REPLY packet body

        Initialise a TACACS+ Authentication REPLY packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys: status, flags, server_msg
        and data. See RFC8907 for details on contents of each.

        Args:
          header(obj): instance of a TACACSPlusHeader class
          body(bytes): byte encoded TACACS+ packet body
          fields(dict): fields used to create packet body
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
            self._status = fields['status']
            self._flags = fields['flags']
            self._server_msg = fields['server_msg']
            self._data = fields['data']
        except KeyError as e:
            msg = '__init__() requires either a byte encoded body or dictionary of fields'
            raise TypeError(msg) from e

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
                self._body += struct.pack('%ds' % len(value), value)
        except struct.error as e:
            raise ValueError('Unable to encode AuthenReply packet. Required' \
                             ' arguments status and flags must be integers') from e
        except TypeError as e:
            raise ValueError('Unable to encode AuthenReply packet. Required' \
                             ' arguments server_msg and data must be strings') from e
        return None
