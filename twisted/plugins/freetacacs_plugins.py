from zope.interface import provider

from twisted.plugin import IPlugin, getPlugins
from twisted.python.usage import Options
from twisted.application.service import IServiceMaker, IService, Service

from freetacacs.service import TACACSPlusService

class CommandLineOptions(Options):
    optParameters = [
        ['user', 'u', None, 'User to run service as'],
        ['group', 'g', None, 'Group to run service as'],
        ]

@provider(IServiceMaker, IPlugin)
class FreeTACACSStart:
    """
    L{IServiceMaker} plugin which gets an L{IService} from an Axiom store
    """

    tapname = "freetacacs-start"
    description = "Run the FreeTACACS server"
    options = CommandLineOptions


    def makeService(cls, options):
        """
        Create an L{IService} for the FreeTACACS server
        """

        service = TACACSPlusService(options)
        return service

    makeService = classmethod(makeService)

__all__ = ['FreeTACACSStart']
