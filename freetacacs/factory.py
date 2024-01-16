"""
Module implements the TACACSPlusFactory class

Classes:
    TACACSPlusFActory

Functions:
    None
"""

from twisted.internet import protocol, reactor
import six

# Local imports
from freetacacs.flags import (TAC_PLUS_AUTHEN, TAC_PLUS_AUTHOR, TAC_PLUS_ACCT)
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStart
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReply

class TACACSPlusProtocol(protocol.Protocol):
    """Define the TACACS+ protocol"""

    def _authentication(self, header, body):
        """Process authentication packets

        Args:
          header(dict): header fields
          body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        if header['sequence_no'] == 1:
            print('authen start')
        else:
            print('authen continue')


    def _authorisation(self, header, body):
        """Process authorisation packets

        Args:
          header(dict): header fields
          body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        if header['sequence_no'] == 1:
            print('author request')
        else:
            print('author response')


    def _accounting(self, header, body):
        """Process accounting packets

        Args:
          header(dict): header fields
          body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        if header['sequence_no'] == 1:
            print('acct request')
        else:
            print('acct response')


    def dataReceived(self, data):
        """Recieve data from network

        Args:
          data(byte): containing raw TACACS+ packet
        Exceptions:
          None
        Returns
          None
        """

        # Decode the TACACS+ packet header
        raw = six.BytesIO(data)
        header = Header.decode(raw.read(12))

        # Determine how we decode the actual packet
        if header['packet_type'] == TAC_PLUS_AUTHEN:
            self._authentication(header, raw.read())

        elif header['packet_type'] == TAC_PLUS_AUTHOR:
            self._authorisation(header, raw.read())

        elif header['packet_type'] == TAC_PLUS_ACCT:
            self._accounting(header, raw.read())
        else:
            print('Unknown packet type')


class TACACSPlusFactory(protocol.Factory):
    """Class providing the TACACS+ factory"""

    protocol = TACACSPlusProtocol

    def getUser(self, user):
        return b"No such user"

if __name__ == "__main__":
    reactor.listenTCP(4949, TACACSPlusFactory())
    print("TACACS+ server listening on port 4949...")
    reactor.run()
