"""
Module provides misc functions

Classes:
    None

Functions:
    create_log_dict
"""

from dataclasses import fields

def create_log_dict(header, body):
    """Build a debug message

    Args:
      header(obj): dataclass containing header fields
      body(obj): dataclass containing body fields
    Exceptions:
      None
    Returns:
      log_args(dict): containing the header/body field key/value pairs
    """

    log_args = {}

    # Add header fields to log_args dict
    for field in fields(header):
        log_args[field.name] = getattr(header, field.name)

    # Add body fields to log_args dict
    for field in fields(body):
        log_args[field.name] = getattr(body, field.name)

    return log_args
