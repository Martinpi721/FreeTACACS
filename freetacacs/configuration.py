"""
Module implements the TACACS+ configuration parsing

Classes:
    None

Functions:
    load_config
    validate_config
"""

import os
import yaml
from twisted.logger import Logger


# Setup the logger
log = Logger()


def load_config(file_path):
    """Load the FreeTACAS+ backend confiugration options

    Args:
      file_path(str): containing path to YAML configuration file
    Exceptions:
      None
    Returns:
      configuration(dict): containing backend config options
    """

    # Set default configuration values
    configuration = {
                       'log_type'     : 'file',
                       'log_file'    : '/var/log/freetacacs/freetacacs.log',
                       'secrets_type': 'file',
                       'secrets_file': '/etc/freetacacs/shared_secrets.json',
                       'auth_type'   : 'pam',
                       'author_type' : 'file',
                       'author_file' : '/etc/freetacacs/authorisations.json',
                   }

    # Open config file and read data
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as e:
        log.warn(message=f'Configuration file {file_path} not found. Using' \
                          ' default configuration settings.')
        return configuration

    # Create configuration dictionary from config file
    for key, value in data.items():
        if key in configuration.keys():
            log.debug(message=f'Configuration key [{key}] updated to value' \
                               ' [{value}].')
            configuration[key] = value

    return configuration


def valid_config(cfg):
    """Load the FreeTACAS+ backend confiugration options

    Args:
      cfg(dict): containing the proposed configuration
    Exceptions:
      None
    Returns:
      valid(bool): configuration is valid/invalid
    """

    # Loop over the configuration dictionary
    for key, value in cfg.items():
        # Check each of these keys
        if key == 'log_dst' or key == 'secrets_type' or key == 'author_type':
            if value != 'file':
                return False

        # Check to see if file exists
        if key == 'log_file' or key == 'secrets_file' or key == 'author_file':
            if not os.path.isfile:
                return False

        # Check auth_type is valid
        if key == 'auth_type' and value != 'pam':
            return False

    return True
