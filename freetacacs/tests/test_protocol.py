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

# Import code to be tested
from freetacacs.protocol import TACACSPlusProtocol


class TestTACACSPlusProtocol(unittest.TestCase):
    """Test class for testing the protocol module"""

    def setUp(self):
        self.protocol = TACACSPlusProtocol()
        self.transport = proto_helpers.StringTransport()
        self.protocol.makeConnection(self.transport)

    def tearDown(self):
        self.protocol.connectionLost(None)

    def test_invalid_tacacs_packet(self):
        """Test that we can handle being sent invalid packets"""

        # Should actually just log a error and continue
        with self.assertRaises(TypeError):
            self.protocol.dataReceived('not_a_tacacs_packet')

        # Assert that the protocol's behavior is as expected
        #self.assertEqual(self.transport.value(), b"Response for some_username\r\n")


