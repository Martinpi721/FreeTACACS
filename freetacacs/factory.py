from twisted.internet import protocol, reactor
from exceptions import PacketAttributeNotSet
from protocol import TACACSPlusProtocol

class TACACSPlusFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return TACACSPlusProtocol()

if __name__ == "__main__":
    reactor.listenTCP(4949, TACACSPlusFactory())
    print("TACACS+ server listening on port 4949...")
    reactor.run()

