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

    flags: int = 0x00
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


@dataclass
class AcctReplyFields(ReplyFields):
    """Defines Accounting Reply packet fields."""


class TACACSPlusAccountRequest(Packet):
    """Class to handle encoding/decoding of TACACS+ Accounting REQUEST packet bodies"""

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


class TACACSPlusAccountReply(Packet):
    """Class to handle encoding/decoding of TACACS+ Accounting REPLY packet bodies"""


        #  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
        #
        # +----------------+----------------+----------------+----------------+
        # |         server_msg len          |            data_len             |
        # +----------------+----------------+----------------+----------------+
        # |     status     |         server_msg ...                           |
        # +----------------+----------------+----------------+----------------+
        # |     data ...                                                      |
        # +----------------+----------------+----------------+----------------+

