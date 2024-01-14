import six
import struct
import hashlib
from twisted.logger import Logger

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet

class TACACSPlusAuthenStart(Packet):
    """Class to handle encoding/decoding of TACACS+ AuthenticationSTART packet bodies"""

    log = Logger()

    @property
    def decode(self):
        """Decode a TACAS+ Authentication start packet body

        Args:
          header(obj): TACACSPlusHeader instance
          byte_body(byte): containing TACACS+ authentication start packet body
          secret(str): containing the TACACS+ shared secret
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

        fields = dict()

        # Deobfuscate the packet if required
        raw = six.BytesIO(self._body)
        if self._secret != None:
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


