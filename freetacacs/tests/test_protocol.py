"""
Module provides unit tests for the protocol module

Classes:
    TestTACACSPlusProtocol

Functions:
    None
"""

from twisted.internet import protocol, defer
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.logger import LogLevel, capturedLogs

# Testing modules to import
from unittest.mock import patch

# Import code to be tested
from freetacacs import flags
from freetacacs.commandline import CommandLineOptions
from freetacacs.service import TACACSPlusService
from freetacacs.protocol import TACACSPlusProtocol
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import AuthenStartFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStartPacket
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReplyPacket


class TestTACACSPlusProtocol(unittest.TestCase):
    """Test class for testing the protocol module"""

    @patch('freetacacs.commandline.os.path.exists')
    @patch('freetacacs.commandline.getpwnam')  # Second call to pwnam
    @patch('freetacacs.commandline.getpass.getuser')
    @patch('freetacacs.commandline.getgrnam')
    @patch('freetacacs.commandline.getpwnam')  # First call to getpwnam
    def setUp(self, mock_getpwnam, mock_getgrnam, mock_getuser,
              mock_get_root_pwnam, mock_path_exists):
        """Setup for all tests"""

        self.data_dir = './freetacacs/tests/data/commandline'

        args = [
                '--user',
                'wheldonm',
                '--group',
                'wheldonm',
                '--port',
                4949,
                '--config',
                '{self.data_dir}/etc/freetacacs.conf',
                '--log',
                f'{self.data_dir}/log/freetacacs.log',
            ]

        options = CommandLineOptions()
        options.parseOptions(args)

        self.protocol = TACACSPlusProtocol()
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)
        self.factory = TACACSPlusService(options)


    def tearDown(self):
        """Tidy up after our test"""

        self.protocol.connectionLost(None)


    def test_invalid_tacacs_packet_not_bytes(self):
        """Test that we can handle being sent invalid packets not byte encode"""

        required_msg = 'NAS 192.168.1.1:54321 connected to 10.0.0.1:12345 sent' \
                       ' a packet that is not byte encoded. Closing connection.'

        with capturedLogs() as events:
            self.protocol.dataReceived('not_a_tacacs_packet')

        event = events[0]
        self.assertTrue(len(events) == 1)
        self.assertEqual(event['server_ip'], '10.0.0.1')
        self.assertEqual(event['server_port'], 12345)
        self.assertEqual(event['nas_ip'], '192.168.1.1')
        self.assertEqual(event['nas_port'], 54321)
        self.assertEqual(event['session_id'], '')
        self.assertEqual(event['sequence_no'], '')
        self.assertEqual(event['log_level'], LogLevel.error)
        self.assertEqual(event['text'], required_msg)
        self.assertEqual(event['log_format'], required_msg)


    def test_invalid_tacacs_packet_bytes(self):
        """Test that we can handle being sent invalid packets"""

        required_msg = 'NAS 192.168.1.1:54321 connected to 10.0.0.1:12345 sent' \
                       ' a packet with a invalid header. Closing connection.'

        with capturedLogs() as events:
            self.protocol.dataReceived(b'not_a_tacacs_packet')

        event = events[0]
        self.assertTrue(len(events) == 1)
        self.assertEqual(event['server_ip'], '10.0.0.1')
        self.assertEqual(event['server_port'], 12345)
        self.assertEqual(event['nas_ip'], '192.168.1.1')
        self.assertEqual(event['nas_port'], 54321)
        self.assertEqual(event['session_id'], 1633645665)
        self.assertEqual(event['sequence_no'], 116)
        self.assertEqual(event['log_level'], LogLevel.error)
        self.assertEqual(event['text'], required_msg)
        self.assertEqual(event['log_format'], required_msg)


    def test_invalid_tacacs_packet_empty(self):
        """Test that we can handle being sent invalid packets"""

        required_msg = 'NAS 192.168.1.1:54321 connected to 10.0.0.1:12345 sent' \
                       ' a packet with a header not meeting TACACS+' \
                       ' specifications. Closing connection.'

        with capturedLogs() as events:
            self.protocol.dataReceived(b'')

        event = events[0]
        self.assertTrue(len(events) == 1)
        self.assertEqual(event['server_ip'], '10.0.0.1')
        self.assertEqual(event['server_port'], 12345)
        self.assertEqual(event['nas_ip'], '192.168.1.1')
        self.assertEqual(event['nas_port'], 54321)
        self.assertEqual(event['session_id'], '')
        self.assertEqual(event['sequence_no'], '')
        self.assertEqual(event['log_level'], LogLevel.error)
        self.assertEqual(event['text'], required_msg)
        self.assertEqual(event['log_format'], required_msg)


    @defer.inlineCallbacks
    def test_selection_of_pap_authentication_flow(self):
        """Test that we can route PAP authentication correctly"""

        # Build a AuthStart packet with PAP auth
        tx_header_fields = HeaderFields(version=193,
                                        packet_type=flags.TAC_PLUS_AUTHEN,
                                        session_id=123456,
                                        sequence_no=1)

        tx_header = Header(tx_header_fields)

        # Build the reply packet body
        tx_body_fields = AuthenStartFields(action=flags.TAC_PLUS_AUTHEN_LOGIN,
                                           authen_type=flags.TAC_PLUS_AUTHEN_TYPE_PAP,
                                           authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                           priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                           user='jsmith',
                                           port='python_tty0',
                                           remote_address='python_device',
                                           data='top_secret')

        start = AuthenStartPacket(tx_header, fields=tx_body_fields,
                                  secret='shared_secret')

        # Mock the necessary functions
        with patch.object(self.factory, 'get_shared_secret') as mock_auth_shared_secret:
            mock_auth_shared_secret.return_value = defer.succeed('shared_secret')

            # Set the factory for the protocol
            self.protocol.factory = self.factory

            # Mock a dummy reply packet for self.transport.write
            # Ensures that the test tidies up correctly
            with patch.object(AuthenReplyPacket, '__bytes__') as mock_reply:
                mock_reply.return_value = bytes(b'dummy packet')

                with capturedLogs() as events:
                    yield self.protocol.dataReceived(bytes(start))

        event = events[0]
        self.assertTrue(len(events) == 2)

        # Start packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 1)
        self.assertEqual(event['length'], 48)

        # Start packet body data
        self.assertEqual(event['action'], flags.TAC_PLUS_AUTHEN_LOGIN)
        self.assertEqual(event['authen_type'], flags.TAC_PLUS_AUTHEN_TYPE_PAP)
        self.assertEqual(event['priv_lvl'], flags.TAC_PLUS_PRIV_LVL_MIN)
        self.assertEqual(event['user'], 'jsmith')
        self.assertEqual(event['port'], 'python_tty0')
        self.assertEqual(event['remote_address'], 'python_device')
        self.assertEqual(event['data'], 'top_secret')

        event = events[1]
        # Reply packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 2)
        self.assertEqual(event['length'], 35)

        # Reply packet body data
        self.assertEqual(event['status'], flags.TAC_PLUS_AUTHEN_STATUS_ERROR)
        self.assertEqual(event['flags'], 0)
        self.assertEqual(event['server_msg'], 'Functionality NOT implemented')
        self.assertEqual(event['data'], '')


    @defer.inlineCallbacks
    def test_selection_of_chap_authentication_flow(self):
        """Test that we can route CHAP authentication correctly"""

        # Build a AuthStart packet with PAP auth
        tx_header_fields = HeaderFields(version=193,
                                        packet_type=flags.TAC_PLUS_AUTHEN,
                                        session_id=123456,
                                        sequence_no=1)

        tx_header = Header(tx_header_fields)

        # Build the reply packet body
        tx_body_fields = AuthenStartFields(action=flags.TAC_PLUS_AUTHEN_LOGIN,
                                           authen_type=flags.TAC_PLUS_AUTHEN_TYPE_CHAP,
                                           authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                           priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                           user='jsmith',
                                           port='python_tty0',
                                           remote_address='python_device',
                                           data='top_secret')

        start = AuthenStartPacket(tx_header, fields=tx_body_fields,
                                  secret='shared_secret')

        # Mock the necessary functions
        with patch.object(self.factory, 'get_shared_secret') as mock_auth_shared_secret:
            mock_auth_shared_secret.return_value = defer.succeed('shared_secret')

            # Set the factory for the protocol
            self.protocol.factory = self.factory

            # Mock a dummy reply packet for self.transport.write
            # Ensures that the test tidies up correctly
            with patch.object(AuthenReplyPacket, '__bytes__') as mock_reply:
                mock_reply.return_value = bytes(b'dummy packet')

                with capturedLogs() as events:
                    yield self.protocol.dataReceived(bytes(start))

        event = events[0]
        self.assertTrue(len(events) == 2)

        # Start packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 1)
        self.assertEqual(event['length'], 48)

        # Start packet body data
        self.assertEqual(event['action'], flags.TAC_PLUS_AUTHEN_LOGIN)
        self.assertEqual(event['authen_type'], flags.TAC_PLUS_AUTHEN_TYPE_CHAP)
        self.assertEqual(event['priv_lvl'], flags.TAC_PLUS_PRIV_LVL_MIN)
        self.assertEqual(event['user'], 'jsmith')
        self.assertEqual(event['port'], 'python_tty0')
        self.assertEqual(event['remote_address'], 'python_device')
        self.assertEqual(event['data'], 'top_secret')

        event = events[1]
        # Reply packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 2)
        self.assertEqual(event['length'], 35)

        # Reply packet body data
        self.assertEqual(event['status'], flags.TAC_PLUS_AUTHEN_STATUS_ERROR)
        self.assertEqual(event['flags'], 0)
        self.assertEqual(event['server_msg'], 'Functionality NOT implemented')
        self.assertEqual(event['data'], '')


    @defer.inlineCallbacks
    def test_selection_of_ascii_authentication_flow(self):
        """Test that we can route ASCII authentication correctly"""

        # Build a AuthStart packet with PAP auth
        tx_header_fields = HeaderFields(version=193,
                                        packet_type=flags.TAC_PLUS_AUTHEN,
                                        session_id=123456,
                                        sequence_no=1)

        tx_header = Header(tx_header_fields)

        # Build the reply packet body
        tx_body_fields = AuthenStartFields(action=flags.TAC_PLUS_AUTHEN_LOGIN,
                                           authen_type=flags.TAC_PLUS_AUTHEN_TYPE_ASCII,
                                           authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                           priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                           user='jsmith',
                                           port='python_tty0',
                                           remote_address='python_device',
                                           data='top_secret')

        start = AuthenStartPacket(tx_header, fields=tx_body_fields,
                                  secret='shared_secret')

        # Mock the necessary functions
        with patch.object(self.factory, 'get_shared_secret') as mock_auth_shared_secret:
            mock_auth_shared_secret.return_value = defer.succeed('shared_secret')

            # Set the factory for the protocol
            self.protocol.factory = self.factory

            # Mock a dummy reply packet for self.transport.write
            # Ensures that the test tidies up correctly
            with patch.object(AuthenReplyPacket, '__bytes__') as mock_reply:
                mock_reply.return_value = bytes(b'dummy packet')

                with capturedLogs() as events:
                    yield self.protocol.dataReceived(bytes(start))

        event = events[0]
        self.assertTrue(len(events) == 2)

        # Start packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 1)
        self.assertEqual(event['length'], 48)

        # Start packet body data
        self.assertEqual(event['action'], flags.TAC_PLUS_AUTHEN_LOGIN)
        self.assertEqual(event['authen_type'], flags.TAC_PLUS_AUTHEN_TYPE_ASCII)
        self.assertEqual(event['priv_lvl'], flags.TAC_PLUS_PRIV_LVL_MIN)
        self.assertEqual(event['user'], 'jsmith')
        self.assertEqual(event['port'], 'python_tty0')
        self.assertEqual(event['remote_address'], 'python_device')
        self.assertEqual(event['data'], 'top_secret')

        event = events[1]
        # Reply packet header data
        self.assertEqual(event['version'], 193)
        self.assertEqual(event['packet_type'], flags.TAC_PLUS_AUTHEN)
        self.assertEqual(event['session_id'], 123456)
        self.assertEqual(event['sequence_no'], 2)
        self.assertEqual(event['length'], 35)

        # Reply packet body data
        self.assertEqual(event['status'], flags.TAC_PLUS_AUTHEN_STATUS_ERROR)
        self.assertEqual(event['flags'], 0)
        self.assertEqual(event['server_msg'], 'Functionality NOT implemented')
        self.assertEqual(event['data'], '')
