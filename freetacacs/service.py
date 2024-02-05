"""
Module implements the TACACS+ service

Classes:
    ITACACSPlusService
    TACACSPlusService

Functions:
    None
"""

import sys
from zope.interface import Interface, implementer

from twisted.python import log
from twisted.internet import defer
from twisted.application import service
from twisted.logger import (Logger,
                            FilteringLogObserver,
                            textFileLogObserver,
                            LogLevelFilterPredicate)

# Local imports
from freetacacs.version import __version__
from freetacacs.configuration import load_config, valid_config
from freetacacs.configuration import ConfigTypeError, ConfigFileError

class ITACACSPlusService(Interface):
    def get_shared_secret(ip):
        """
        Return a deferred returning L{bytes}.
        """


@implementer(ITACACSPlusService)
class TACACSPlusService(service.Service):
    """Class providing the TACACS+ service"""

    # Setup the logger
    log = Logger()

    def __init__(self, options):
        """Load backend configuration, shared secrets, authentication and
        authorisation data

        Args:
          options(dict): containing FreeTACACS command line options
        Exceptions:
          None
        Returns
          None
        """

#        import pdb; pdb.set_trace()
        self.cfg = options

        # Setup logging
        fileObserver = textFileLogObserver(open(self.cfg['log'], 'a'))
        if self.cfg['debug']:
            predicate = LogLevelFilterPredicate(defaultLogLevel=log.LogLevel.debug)
            fObserver = FilteringLogObserver(observer=fileObserver, predicates=predicate)
            self.log = Logger(observer=fObserver)
        else:
            self.log = Logger(observer=fileObserver)

        self.log.info(f"FreeTACACS {__version__} starting up.")

        # Create a single configuration dictionary
        self.cfg.update(load_config(self.cfg['config']))

        try:
            valid_config(self.cfg)
        except (ConfigTypeError, ConfigFileError) as e:
            self.log.critical(str(e))
            sys,exit(1)

        self.log.info(f"Configuration loaded from {self.cfg['config']}.")

        # Load shared secrets from file if we are using a file backend
        if self.cfg['secrets_type'] == 'file':
            self.secrets = { '127.0.0.1': 'test' }
            self.log.info(f"Shared secrets loaded from {self.cfg['secrets_file']}.")

        # Load credentials from file if we are using a file backend
        if self.cfg['auth_type'] == 'file':
            self.credentials = { 'test': 'test' }
            self.log.info(f"Authentication credentials loaded from {self.cfg['auth_file']}.")

        # Load authorisation from file if we are using a file backend
        if self.cfg['author_type'] == 'file':
            self.authorisations = { 'test': 'test' }
            self.log.info(f"Authorisations loaded from {self.cfg['author_file']}.")

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
        self.log.info("FreeTACACS ready to answer client requests.")
        service.Service.startService(self)

    def stopService(self):
        self.log.info("FreeTACACS has been requested to shut down.")
        service.Service.stopService(self)
