from zope.interface import provider

from twisted.plugin import IPlugin, getPlugins
from twisted.python.usage import Options
from twisted.application.service import IServiceMaker, IService, Service

from freetacacs.service import TACACSPlusService

@provider(IServiceMaker, IPlugin)
class FreeTACACSStart:
    """
    L{IServiceMaker} plugin which gets an L{IService} from an Axiom store
    """

    tapname = "freetacacs-start"
    description = "Run the FreeTACACS server"

    class options(Options):
        optParameters = [
            ('dbdir', 'd', None, 'Path containing Axiom database to start'),
            ('journal-mode', None, None, 'SQLite journal mode to set'),
            ]

        optFlags = [('debug', 'b', 'Enable Axiom-level debug logging')]


    def makeService(cls, options):
        """
        Create an L{IService} for the FreeTACACS server
        """
        return TACACSPlusService()

    makeService = classmethod(makeService)

__all__ = ['FreeTACACSStart']
