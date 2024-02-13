"""
Module provides unit tests for the protocol module

Classes:
    TestTACACSPlusProtocol

Functions:
    None
"""

from twisted.internet import protocol
from twisted.trial import unittest
from twisted.test import proto_helpers
from twisted.logger import LogLevel, capturedLogs

# Testing modules to import
from unittest.mock import patch

# Import code to be tested
from freetacacs.protocol import TACACSPlusProtocol


class TestTACACSPlusProtocol(unittest.TestCase):
    """Test class for testing the protocol module"""

    def setUp(self):
        """Setup for all tests"""

        self.protocol = TACACSPlusProtocol()
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)


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
