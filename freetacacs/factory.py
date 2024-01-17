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
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import ReplyPacketFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStart
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReply

class TACACSPlusProtocol(protocol.Protocol):
    """Define the TACACS+ protocol"""

    def _authentication(self, rx_header, rx_body):
        """Process authentication packets

        Args:
          rx_header(dict): header fields
          rx_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        # AuthenSTART
        if rx_header.sequence_no == 1:
            print('authen start')
            seq_no = rx_header.sequence_no + 1
            tx_header = Header(HeaderFields(rx_header.version,
                                            flags.TAC_PLUS_AUTHEN,
                                            rx_header.session_id, 0), seq_no)

            fields = ReplyPacketFields(flags.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                                       flags.TAC_PLUS_REPLY_FLAG_NOECHO,
                                       'test', 'test')

            reply = AuthenReply(tx_header, fields=fields, secret='test')
            self.transport.write(bytes(reply))

        # AuthenCONTINUE
        else:
            print('authen continue')


    def _authorisation(self, rx_header, rx_body):
        """Process authorisation packets

        Args:
          rx_header(dict): header fields
          rx_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        if rx_header.sequence_no == 1:
            print('author request')
        else:
            print('author response')


    def _accounting(self, rx_header, rx_body):
        """Process accounting packets

        Args:
          rx_header(dict): header fields
          rx_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        if rx_header.sequence_no == 1:
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
        rx_header = Header.decode(raw.read(12))

        # Determine how we decode the actual packet
        if rx_header.packet_type == flags.TAC_PLUS_AUTHEN:
            self._authentication(rx_header, raw.read())

        elif rx_header.packet_type == flags.TAC_PLUS_AUTHOR:
            self._authorisation(header, raw.read())

        elif rx_header.packet_type == flags.TAC_PLUS_ACCT:
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
