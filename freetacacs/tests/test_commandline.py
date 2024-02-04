"""
Module provides unit tests for the commandline module

Classes:
    TestCommandLineOptions

Functions:
    None
"""

import sys
from io import StringIO

from twisted.trial import unittest
from twisted.python.usage import UsageError

from unittest.mock import patch

# Import code to be tested
from freetacacs.commandline import CommandLineOptions


class TestCommandLineOptions(unittest.TestCase):
    """Class to test the CommandLineOptions class"""

    @patch('freetacacs.commandline.getpwnam')  # Second call to pwnam
    @patch('freetacacs.commandline.getpass.getuser')
    @patch('freetacacs.commandline.getgrnam')
    @patch('freetacacs.commandline.getpwnam')  # First call to getpwnam
    def test_default_commandline_options(self,
                                           mock_getpwnam,
                                           mock_getgrnam,
                                           mock_getuser,
                                           mock_get_root_pwnam):
        """Test we handle the default commandline options"""

        args = []

        mock_getpwnam.return_value.pw_uid = 123
        mock_get_root_pwnam.return_value.pw_uid = 0
        mock_getgrnam.return_value.gr_gid = 456
        mock_getuser.return_value = 'root'

        options = CommandLineOptions()
        options.parseOptions(args)

        self.assertEqual(options['user'], 'freetacacs')
        self.assertEqual(options['group'], 'freetacacs')
        self.assertEqual(options['port'], 49)
        self.assertEqual(options['config'], '/etc/freetacacs/freetacacs.conf')
        self.assertFalse(options['debug'])


    def test_version(self):
        """Test the commandline option version works"""

        args = [
                '--version',
               ]

        # Capture text sent to stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        with self.assertRaises(SystemExit):
            options = CommandLineOptions()
            options.parseOptions(args)

        # Return stdout to previous state
        sys.stdout = sys.__stdout__

        versions = captured_output.getvalue().strip().splitlines()

        self.assertEqual(versions[0], 'FreeTACACS version: 0.0.1')
        self.assertEqual(versions[1], 'Twisted version: 23.10.0')


    @patch('freetacacs.commandline.getpwnam')  # Second call to pwnam
    @patch('freetacacs.commandline.getpass.getuser')
    @patch('freetacacs.commandline.getgrnam')
    @patch('freetacacs.commandline.getpwnam')  # First call to getpwnam
    def test_setting_debug_flag(self, mock_getpwnam,
                                mock_getgrnam, mock_getuser,
                                mock_get_current_user_pwnam):
        """Test we handle setting the debug flag"""

        args = ['--debug']

        mock_getpwnam.return_value.pw_uid = 123
        mock_get_current_user_pwnam.return_value.pw_uid = 0
        mock_getgrnam.return_value.gr_gid = 456
        mock_getuser.return_value = 'root'

        options = CommandLineOptions()
        options.parseOptions(args)

        self.assertEqual(options['user'], 'freetacacs')
        self.assertEqual(options['group'], 'freetacacs')
        self.assertEqual(options['port'], 49)
        self.assertEqual(options['config'], '/etc/freetacacs/freetacacs.conf')
        self.assertTrue(options['debug'])


    @patch('freetacacs.commandline.getpwnam')  # Second call to pwnam
    @patch('freetacacs.commandline.getpass.getuser')
    @patch('freetacacs.commandline.getgrnam')
    @patch('freetacacs.commandline.getpwnam')  # First call to getpwnam
    def test_start_user_with_insufficient_privs(self,
                                                mock_getpwnam,
                                                mock_getgrnam,
                                                mock_getuser,
                                                mock_get_current_user_pwnam):
        """Test we handle the process start user without root access"""

        args = []

        mock_getpwnam.return_value.pw_uid = 123
        mock_get_current_user_pwnam.return_value.pw_uid = 1000
        mock_getgrnam.return_value.gr_gid = 456
        mock_getuser.return_value = 'jsmith'

        with self.assertRaises(UsageError) as e:
            options = CommandLineOptions()
            options.parseOptions(args)

        self.assertEqual(str(e.exception), 'User freetacacs cannot start a' \
                                           ' service on port 49. Insufficient' \
                                           ' privilege.')


    @patch('freetacacs.commandline.getpwnam')  # Second call to pwnam
    @patch('freetacacs.commandline.getpass.getuser')
    @patch('freetacacs.commandline.getgrnam')
    @patch('freetacacs.commandline.getpwnam')  # First call to getpwnam
    def test_setting_all_options(self,
                                           mock_getpwnam,
                                           mock_getgrnam,
                                           mock_getuser,
                                           mock_get_current_user_pwnam):
        """Test we handle setting all commandline options"""

        args = [
                '--user',
                'jsmith',
                '--group',
                'jsmith',
                '--port',
                4949,
                '--debug',
                '--config',
                '/etc/freetacacs.conf',
            ]

        mock_getpwnam.return_value.pw_uid = 123
        mock_get_current_user_pwnam.return_value.pw_uid = 1000
        mock_getgrnam.return_value.gr_gid = 456
        mock_getuser.return_value = 'jdoe'

        options = CommandLineOptions()
        options.parseOptions(args)

        self.assertEqual(options['user'], 'jsmith')
        self.assertEqual(options['group'], 'jsmith')
        self.assertEqual(options['port'], '4949')
        self.assertEqual(options['config'], '/etc/freetacacs.conf')
        self.assertTrue(options['debug'])
