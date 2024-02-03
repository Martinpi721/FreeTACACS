"""
Module provides unit tests for the configuration module

Classes:
    TestConfiguration
    TestValidConfig

Functions:
    None
"""

from twisted.trial import unittest
from twisted.logger import LogLevel
from twisted.python import log

# Import code to be tested
from freetacacs.configuration import load_config, valid_config


class TestConfiguration(unittest.TestCase):
    """Class to test the load_config function"""

    def setUp(self) -> None:
        """Setup for all tests"""

        self.data_dir = './freetacacs/tests/data'

        # Log capture
        self.catcher: list[log.EventDict] = []
        self.observer = self.catcher.append
        log.addObserver(self.observer)
        self.addCleanup(log.removeObserver, self.observer)


    def test_configuration_defaults(self):
        """Test we can handle a missing configuration file"""

        required_cfg = {
                         'log_dst'     : 'file',
                         'log_file'    : '/var/log/freetacacs/freetacacs.log',
                         'secrets_type': 'file',
                         'secrets_file': '/etc/freetacacs/shared_secrets.json',
                         'auth_type'   : 'pam',
                         'author_type' : 'file',
                         'author_file' : '/etc/freetacacs/authorisations.json',
                        }

        required_log = {
                         'msg': 'Configuration file /tmp/missing not found.' \
                                ' Using default configuration settings.',
                         'level': LogLevel.warn,
                         'namespace': 'freetacacs.configuration',
                        }

        # Initialise log capture
        catcher = self.catcher

        # Call the function that contains Twisted logger messages
        cfg = load_config('/tmp/missing')

        # Extract the log event from out log capture
        msg = catcher.pop()

        # Verify we havea default config and the logging is sane
        self.assertDictEqual(cfg, required_cfg)
        self.assertEqual(msg['message'], required_log['msg'])
        self.assertEqual(msg['log_level'], required_log['level'])
        self.assertEqual(msg['log_namespace'], required_log['namespace'])


    def test_valid_json_with_valid_keys(self):
        """Test we handle a yaml file with valid data set"""

        required_cfg = {
                         'log_dst'     : 'file',
                         'log_file'    : '/var/log/freetacacs.log',
                         'secrets_type': 'file',
                         'secrets_file': '/etc/shared_secrets.json',
                         'auth_type': 'pam',
                         'author_type': 'file',
                         'author_file': '/etc/authorisations.json',
                    }

        file_path = f"{self.data_dir}/configuration/config.json"
        cfg = load_config(file_path)

        self.assertDictEqual(cfg, required_cfg)


    def test_valid_yaml_with_valid_keys(self):
        """Test we handle a yaml file with valid data set"""

        required_cfg = {
                         'log_dst'     : 'file',
                         'log_file'    : '/var/log/freetacacs.log',
                         'secrets_type': 'file',
                         'secrets_file': '/etc/shared_secrets.json',
                         'auth_type': 'pam',
                         'author_type': 'file',
                         'author_file': '/etc/authorisations.json',
                    }

        file_path = f"{self.data_dir}/configuration/config.yaml"
        cfg = load_config(file_path)

        self.assertDictEqual(cfg, required_cfg)


class TestValidConfig(unittest.TestCase):
    """Class to test the valid_config function"""

    def setUp(self) -> None:
        """Setup for all tests"""

        self.data_dir = './freetacacs/tests/data'

    def test_valid_configuration(self):
        """Test that the default configuration is valid"""

        cfg = {
                 'log_dst'     : 'file',
                 'log_file'    : '/var/log/freetacacs.log',
                 'secrets_type': 'file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'pam',
                 'author_type': 'file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertTrue(valid_config(cfg))


    def test_invalid_log_dst(self):
        """Test that we can validate log_dst"""

        cfg = {
                 'log_dst'     : 'not_a_file',
                 'log_file'    : '/var/log/freetacacs.log',
                 'secrets_type': 'file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'pam',
                 'author_type': 'file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertFalse(valid_config(cfg))


    def test_invalid_secrets_type(self):
        """Test that we can validate secrets_type"""

        cfg = {
                 'log_dst'     : 'file',
                 'log_file'    : '/var/log/freetacacs.log',
                 'secrets_type': 'not_a_file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'pam',
                 'author_type': 'file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertFalse(valid_config(cfg))


    def test_invalid_author_type(self):
        """Test that we can validate author_type"""

        cfg = {
                 'log_dst'     : 'file',
                 'log_file'    : '/var/log/freetacacs.log',
                 'secrets_type': 'file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'pam',
                 'author_type': 'not_a_file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertFalse(valid_config(cfg))


    def test_invalid_auth_type(self):
        """Test that we can validate auth_type"""

        cfg = {
                 'log_dst'     : 'file',
                 'log_file'    : '/var/log/freetacacs.log',
                 'secrets_type': 'file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'not_pam',
                 'author_type': 'file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertFalse(valid_config(cfg))


    def test_missing_log_file(self):
        """Test that log_file value exists"""

        cfg = {
                 'log_dst'     : 'file',
                 'log_file'    : f'{self.data_dir}/var/log/freetacacs.log',
                 'secrets_type': 'file',
                 'secrets_file': '/etc/shared_secrets.json',
                 'auth_type': 'not_pam',
                 'author_type': 'file',
                 'author_file': '/etc/authorisations.json',
            }

        self.assertFalse(valid_config(cfg))
