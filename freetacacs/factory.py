"""
Module implements the TACACS+ factory

Classes:
    ITACACSPlusFactory
    TACACSPlusFactoryFromService

Functions:
    None
"""

from zope.interface import Interface, implementer

from twisted.internet import protocol
from twisted.python import components

# Local imports
from freetacacs.service import ITACACSPlusService
from freetacacs.protocol import TACACSPlusProtocol


class ITACACSPlusFactory(Interface):
    def get_shared_credentials(ip):
        """
        Return a deferred returning L{bytes}
        """

    def buildProtocol(addr):
        """
        Return a protocol returning L{bytes}
        """


@implementer(ITACACSPlusFactory)
class TACACSPlusFactoryFromService(protocol.ServerFactory):
    protocol = TACACSPlusProtocol

    def __init__(self, service):
        self.service = service

    def get_shared_secret(self, ip):
        return self.service.get_shared_secret(ip)


components.registerAdapter(TACACSPlusFactoryFromService, ITACACSPlusService, ITACACSPlusFactory)
