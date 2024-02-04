"""
FreeTACACS plugin for Twisted.

Classes:
    CommandLineOptions

Functions:
    None
"""

import sys
import getpass

from pwd import getpwnam
from grp import getgrnam

from twisted import copyright
from twisted.python.usage import Options, UsageError

# Local imports
from freetacacs import version


class CommandLineOptions(Options):
    """Class to handle parsing twistd commandline options"""

    # Set command line parameters
    optParameters = [
                # NOTE: we load additional configuration in after service start
                ['config', 'c', '/etc/freetacacs/freetacacs.conf',
                 'Configuration file path.'],
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

        print(f'FreeTACACS version: {version.__version__}')
        print(f'Twisted version: {copyright.version}')
        sys.exit(0)


    def postOptions(self):
        """
        Override the default postOptions method to carry out
        validation of commandline options
        """

        # Check that user and group both exist
        try:
            getpwnam(f"{self['user']}").pw_uid      # Returns UID only
            getgrnam(f"{self['group']}").gr_gid     # Returns GID only
        except KeyError as e:
            if str(e).startswith('"getpwnam'):
                raise UsageError(f"User {self['user']} not found.")

            if str(e).startswith('"getgrnam'):
                raise UsageError(f"Group {self['group']} not found.")

        # Get username of user running script
        current_user = getpass.getuser()
        current_uid = getpwnam(f'{current_user}').pw_uid

        # Check if user has ability to start a service on a low port
        if int(self['port']) < 1024 and current_uid != 0:
            raise UsageError(f"User {self['user']} cannot start a service on port" \
                             f" {self['port']}. Insufficient privilege.")
