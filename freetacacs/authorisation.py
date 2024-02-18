"""
Module implements TACACS+ authorisation packets

Classes:
    TACACSPlusAuthorRequest
    TACACSPlusAuthorResponse

Functions:
    None
"""
import struct
from dataclasses import dataclass
import six

# Local imports
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet


@dataclass
class AuthorRequestFields:
    """Defines Authorisation Request packet fields"""
    authen_method: int = 0x00
    priv_lvl: int = 0x00
    authen_type: int = 0x00
    service: int = 0x00
    user: str = ''
    port: str = ''
    remote_address: str = ''
    arg_cnt: int = 0


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

        if not isinstance(self.service, int):
            raise TypeError('Service should be of type int')

        if not isinstance(self.user, str):
            raise TypeError('User should be of type string')

        if not isinstance(self.port, str):
            raise TypeError('Port should be of type string')

        if not isinstance(self.remote_address, str):
            raise TypeError('Remote Address should be of type string')

        if not isinstance(self.arg_cnt, int):
            raise TypeError('Argument Count should be of type int')


    def __str__(self):
        """String representation of the authorisation request fields

        Args:
          None
        Exceptions:
          None
        Returns:
          fields(str): containing the authorisation request fields
        """
        pass


class TACACSPlusAuthorRequest(Packet):
    """Class to handle encoding/decoding of TACACS+ Authorisation REQUEST packet bodies"""

    def __init__(self, header, body=six.b(''),
                 fields=AuthorRequestFields(),
                 secret=None):
        """Initialise a TACACS+ Authorisation REQUEST packet body

        Initialise a TACACS+ Authorisation REQUEST packet. This can be done by
        either passing a byte body(when decoding) or passing values in a fields
        dict(when creating).

        Fields dict must contain the following keys:
        See RFC8907 for details on contents of each.

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

