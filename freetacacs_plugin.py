import os
import sys

from twisted.application import service, strports
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString

# Update path to get twistd to import modules corretly
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from freetacacs.factory import TACACSPlusFactory

# Startup the app
application = service.Application("freetacacs", uid=1, gid=1)
factory = TACACSPlusFactory()

strports.service("tcp:4949",
                 factory,
                 reactor=reactor).setServiceParent(service.IServiceCollection(application))
