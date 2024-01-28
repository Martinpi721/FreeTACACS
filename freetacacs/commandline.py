"""
FreeTACACS plugin for Twisted.

Classes:
    CommandLineOptions

Functions:
    None
"""

import sys
from configargparse import ArgParser
from twisted.python.usage import Options


class CommandLineOptions(Options):
    """Class to handle parsing twistd commandline options"""

    # Set command line parameters
    optParameters = [
                # NOTE: we load additional configuration in after service start
                ['config', 'c', '/etc/freetacacs/freetacacs.conf', 'Configuration file path.'],
                ['group', 'g', 'freetacacs', 'Group to run service as.'],
                ['port', 'p', 49, 'Port for service to listen on.'],
                ['user', 'u', 'freetacacs', 'User to run service as.'],
            ]

    # Set command line flags
    optFlags = [['debug', 'd', 'Enable debug logging.']]

    def opt_version(self):
        """
        Override the default version function to display FreeTACACS version
        in addition to the twisted version
        """
        from twisted import copyright
        from freetacacs import version

        print(f'FreeTACACS version: {version.__version__}')
        print(f'Twisted version: {copyright.version}')
        sys.exit(0)

