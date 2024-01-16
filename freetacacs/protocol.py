"""
Module implements the TACACS+ protocol

Classes:
    TACACSPlusProtocol

Functions:
    None
"""

from twisted.protocols import basic

#from freetacacs.packet import TACACSPlusPacket as Packet
#from freetacacs.header import TACACSPlusHeader as Header

class TACACSPlusProtocol(basic.LineReceiver):
    """Define the TACACS+ protocol"""

    def connectionMade(self):
        """Run when a client makes a connection"""
        print("Connection made from", self.transport.getPeer())


    def connectionLost(self, reason):
        """Run when a client disconnects"""
        print("Connection lost from", self.transport.getPeer())


    def dataReceived(self, data):
        # Process incoming data if needed
        print("Received data:", data)
