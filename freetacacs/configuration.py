"""
Module implements the TACACS+ configuration parsing

Classes:
    None

Functions:
    load_config
"""

import yaml

def load_config(file_path):
    """Load the FreeTACAS+ backend confiugration options

    Args:
      file_path(str): containing path to YAML configuration file
    Exceptions:
      FileNotFoundError
    Returns:
      configuration(dict): containing backend config options
    """

    configuration = {}

    # List of valid keys so we can dump invalid ones easily
    valid_keys = [
                   'secrets_type',
                   'secrets_file',
                   'auth_type',
                   'author_type',
                   'author_file',
                 ]

    # Open config file and read data
    try:
        with open(file_path, 'r') as file:
         data = yaml.safe_load(file)
    except FileNotFoundError as e:
        raise

    # Create configuration dictionary from config file
    for key, value in data.items():
        if key in valid_keys:
            configuration[key] = value

    return configuration
