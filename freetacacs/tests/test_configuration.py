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
from freetacacs.configuration import ConfigTypeError, ConfigFileError


class TestConfiguration(unittest.TestCase):
    """Class to test the load_config function"""

    def setUp(self) -> None:
        """Setup for all tests"""

        self.data_dir = './freetacacs/tests/data/configuration'

        # Log capture
        self.catcher: list[log.EventDict] = []
        self.observer = self.catcher.append
        log.addObserver(self.observer)
        self.addCleanup(log.removeObserver, self.observer)


    def test_configuration_defaults(self):
        """Test we can handle a missing configuration file"""

        required_cfg = {
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
                         'secrets_type': 'file',
                         'secrets_file': '/etc/shared_secrets.json',
                         'auth_type': 'pam',
                         'author_type': 'file',
                         'author_file': '/etc/authorisations.json',
                    }

        file_path = f"{self.data_dir}/etc/config.json"
        cfg = load_config(file_path)

        self.assertDictEqual(cfg, required_cfg)


    def test_valid_yaml_with_valid_keys(self):
        """Test we handle a yaml file with valid data set"""

        required_cfg = {
                         'secrets_type': 'file',
                         'secrets_file': '/etc/shared_secrets.json',
                         'auth_type': 'pam',
                         'author_type': 'file',
                         'author_file': '/etc/authorisations.json',
                    }

        file_path = f"{self.data_dir}/etc/config.yaml"
        cfg = load_config(file_path)

        self.assertDictEqual(cfg, required_cfg)


class TestValidConfig(unittest.TestCase):
    """Class to test the valid_config function"""

    def setUp(self) -> None:
        """Setup for all tests"""

        self.data_dir = './freetacacs/tests/data/configuration'

        # Log capture
        self.catcher: list[log.EventDict] = []
        self.observer = self.catcher.append
        log.addObserver(self.observer)
        self.addCleanup(log.removeObserver, self.observer)

    def test_valid_configuration(self):
        """Test that the a configuration is valid"""

        cfg = {
                 'secrets_type': 'file',
                 'secrets_file': f'{self.data_dir}/etc/shared_secrets.json',
                 'auth_type'   : 'pam',
                 'author_type' : 'file',
                 'author_file' : f'{self.data_dir}/etc/authorisations.json',
            }

        # Initialise log capture
        catcher = self.catcher

        self.assertIsNone(valid_config(cfg))

        # Extract the first log event from out log capture and test values
        msg = catcher.pop()
        self.assertEqual(msg['message'], 'Configuration key [author_file] set to ' \
                         '[./freetacacs/tests/data/configuration/etc/authorisations.json].')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')

        # Extract the second log event from out log capture and test values
        msg = catcher.pop()
        self.assertEqual(msg['message'], 'Configuration key [author_type] set to [file].')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')


    def test_invalid_secrets_type(self):
        """Test that we can validate secrets_type"""

        cfg = {
                 'secrets_type': 'not_a_file',
                 'secrets_file': f'{self.data_dir}/etc/shared_secrets.json',
                 'auth_type'   : 'pam',
                 'author_type' : 'file',
                 'author_file' : f'{self.data_dir}/etc/authorisations.json',
            }

        # Initialise log capture
        catcher = self.catcher

        with self.assertRaises(ConfigTypeError) as e:
            valid_config(cfg)

        self.assertIn(str(e.exception), 'Config option secrets_type has invalid' \
                                        ' value [not_a_file].')

        # Extract the last log event from out log capture and test values
        msg = catcher[-1]
        self.assertEqual(msg['message'], 'Config option secrets_type has invalid' \
                                         ' value [not_a_file].')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')


    def test_invalid_author_type(self):
        """Test that we can validate author_type"""

        cfg = {
                 'secrets_type': 'file',
                 'secrets_file': f'{self.data_dir}/etc/shared_secrets.json',
                 'auth_type'   : 'pam',
                 'author_type' : 'not_a_file',
                 'author_file' : f'{self.data_dir}/etc/authorisations.json',
            }

        # Initialise log capture
        catcher = self.catcher

        with self.assertRaises(ConfigTypeError) as e:
            valid_config(cfg)

        self.assertIn(str(e.exception), 'Config option author_type has invalid' \
                                        ' value [not_a_file].')

        # Extract the last log event from out log capture and test values
        msg = catcher[-1]
        self.assertEqual(msg['message'], 'Config option author_type has invalid' \
                                         ' value [not_a_file].')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')


    def test_invalid_auth_type(self):
        """Test that we can validate auth_type"""

        cfg = {
                 'secrets_type': 'file',
                 'secrets_file': f'{self.data_dir}/etc/shared_secrets.json',
                 'auth_type'   : 'not_pam',
                 'author_type' : 'file',
                 'author_file' : f'{self.data_dir}/etc/authorisations.json',
            }

        # Initialise log capture
        catcher = self.catcher

        with self.assertRaises(ConfigTypeError) as e:
            valid_config(cfg)

        self.assertIn(str(e.exception), 'Config option auth_type has invalid' \
                                        ' value [not_pam].')

        # Extract the last log event from out log capture and test values
        msg = catcher[-1]
        self.assertEqual(msg['message'], 'Config option auth_type has invalid' \
                                         ' value [not_pam].')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')


    def test_missing_share_secrets_file(self):
        """Test that secrets_file value exists"""

        cfg = {
                 'secrets_type': 'file',
                 'secrets_file': f'{self.data_dir}/etc/missing.json',
                 'auth_type'   : 'pam',
                 'author_type' : 'file',
                 'author_file' : f'{self.data_dir}/etc/authorisations.json',
            }

        # Initialise log capture
        catcher = self.catcher

        with self.assertRaises(ConfigFileError) as e:
            valid_config(cfg)

        self.assertIn(str(e.exception), 'Unable to find file' \
                      ' ./freetacacs/tests/data/configuration/etc/missing.json' \
                      ' specified by configuration option secrets_file.')

        # Extract the last log event from out log capture and test values
        msg = catcher[-1]
        self.assertEqual(msg['message'], 'Unable to find file' \
                      ' ./freetacacs/tests/data/configuration/etc/missing.json' \
                      ' specified by configuration option secrets_file.')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')


    def test_missing_authorisations_file(self):
        """Test that author_file value exists"""

        cfg = {
                 'secrets_type': 'file',
                 'secrets_file': f'{self.data_dir}/etc/shared_secrets.json',
                 'auth_type'   : 'pam',
                 'author_type' : 'file',
                 'author_file' : f'{self.data_dir}/etc/missing.json',
            }

        # Initialise log capture
        catcher = self.catcher

        with self.assertRaises(ConfigFileError) as e:
            valid_config(cfg)

        self.assertIn(str(e.exception), 'Unable to find file' \
                      ' ./freetacacs/tests/data/configuration/etc/missing.json' \
                      ' specified by configuration option author_file.')

        # Extract the last log event from out log capture and test values
        msg = catcher[-1]
        self.assertEqual(msg['message'], 'Unable to find file' \
                      ' ./freetacacs/tests/data/configuration/etc/missing.json' \
                      ' specified by configuration option author_file.')
        self.assertEqual(msg['log_level'], LogLevel.debug)
        self.assertEqual(msg['log_namespace'], 'freetacacs.configuration')
