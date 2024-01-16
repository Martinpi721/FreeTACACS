"""
Module implements the TACACSPlusFactory class

Classes:
    TACACSPlusFActory

Functions:
    None
"""

from twisted.internet import protocol, reactor
#from freetacacs.exceptions import PacketAttributeNotSet
from freetacacs.protocol import TACACSPlusProtocol

class TACACSPlusFactory(protocol.Factory):
    """Class providing the TACACS+ factory"""

    def buildProtocol(self, addr):
        """Create the TACACS+ protocol

        Args:
          addr():
        Exceptions:
          None
        Returns:
          None
        """

        return TACACSPlusProtocol()

if __name__ == "__main__":
    reactor.listenTCP(4949, TACACSPlusFactory())
    print("TACACS+ server listening on port 4949...")
    reactor.run()
