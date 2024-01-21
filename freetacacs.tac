import os
import sys

from twisted.application import service, strports
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString

# Update path to get twistd to import modules corretly
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Local imports
from freetacacs.factory import ITACACSPlusFactory
from freetacacs.service import TACACSPlusService

# Startup the app
application = service.Application("freetacacs", uid=1, gid=1)
f = TACACSPlusService()

serviceCollection = service.IServiceCollection(application)
f.setServiceParent(serviceCollection)
strports.service("tcp:49", ITACACSPlusFactory(f)).setServiceParent(serviceCollection)
