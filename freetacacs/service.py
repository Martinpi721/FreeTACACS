"""
Module implements the TACACS+ service

Classes:
    ITACACSPlusService
    TACACSPlusService

Functions:
    None
"""

from zope.interface import Interface, implementer

from twisted.internet import defer
from twisted.application import service

# Local imports

class ITACACSPlusService(Interface):
    def get_shared_secret(ip):
        """
        Return a deferred returning L{bytes}.
        """


@implementer(ITACACSPlusService)
class TACACSPlusService(service.Service):
    """Class providing the TACACS+ service"""

    def __init__(self):
        self.secrets = { '127.0.0.1': 'test' }
        self.credentials = { 'test': 'test' }
        self.ip_address = ''

    def get_shared_secret(self, ip):
        """Lookup the client shared secret value from the clients ip address

        Args:
          ip(str): containing clients ip address
        Exceptions:
          None
        Returns
          secret(str): containing the shared secret key
        """

        return defer.succeed(self.secrets.get(ip, b"No such device"))

    def valid_credentials(self, username, password):
        """Lookup the client shared secret value from the clients ip address

        Args:
          username(str): containing user accessing client device
          password(str): containing password for user account
        Exceptions:
          None
        Returns
          secret(str): containing the shared secret key
        """

        return defer.succeed(self.credentials.get(True, False))

    def startService(self):
        service.Service.startService(self)

    def stopService(self):
        service.Service.stopService(self)
