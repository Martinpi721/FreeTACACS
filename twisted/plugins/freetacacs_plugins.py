"""
FreeTACACS plugin for Twisted.

Classes:
    FreeTACACSStart

Functions:
    None
"""

import sys

from pwd import getpwnam
from grp import getgrnam

from zope.interface import provider

from twisted.plugin import IPlugin
from twisted.application import service, strports
from twisted.application.service import IServiceMaker

# Local imports
from freetacacs.commandline import CommandLineOptions
from freetacacs.service import TACACSPlusService

@provider(IServiceMaker, IPlugin)
class FreeTACACSStart:
    """
    L{IServiceMaker} plugin which gets an L{IService} from an FreeTACACS
    """

    tapname = "freetacacs-start"
    description = "Run the FreeTACACS server"
    options = CommandLineOptions


    def makeService(cls, options):
        """
        Create an L{IService} for the FreeTACACS server
        """

        from freetacacs.factory import ITACACSPlusFactory

        # Setup the TACACS+ server service
        s = service.MultiService()
        f = TACACSPlusService(options)

        # Set the uid/gid to run the service as
        f.setServiceParent(s)
        f.uid = getpwnam(f"{options['user']}").pw_uid      # Returns UID only
        f.gid = getgrnam(f"{options['group']}").gr_gid     # Returns GID only

        # Set the tcp port no. to listen on
        h = strports.service(f"tcp:{options['port']}", ITACACSPlusFactory(f))
        h.setServiceParent(s)

        return s

    makeService = classmethod(makeService)

__all__ = ['FreeTACACSStart']
