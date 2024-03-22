"""
Module implements the projects custom exceptions

Classes:
    ConfigTypeError
    ConfigFileError

Functions:
    None
"""

# Configuration exceptions
class ConfigTypeError(Exception):
    """Raised when a configuration _type option is invalid"""


class ConfigFileError(Exception):
    """Raised when a configuration _file option is invalid"""

# Packet exceptions
class MissingServiceArgument(Exception):
    """Raised when authorisation args do not include a service argument"""


class MissingCmdArgument(Exception):
    """Raised when authorisation arg service=shell but no cmd provided"""


class InvalidChapVersion(Exception):
    """Raised when a invalid chap version is passed to the chap encode/decode property"""


class InvalidPppPeerId(Exception):
    """Raised when a invalid PPP Peer Id is encountered"""
