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
from freetacacs.authentication import AuthenReplyFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStartPacket
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReplyPacket

class TACACSPlusProtocol(protocol.Protocol):
    """Define the TACACS+ protocol"""

    def __init__(self):
        """Create mapper dictionaries

        Args:
          None
        Exceptions:
          None
        Returns:
          None
        """

        self.packet_type_mapper = {
                'TAC_PLUS_AUTHEN': self._authentication,
                0x01             : self._authentication,
                'TAC_PLUS_AUTHOR': self._authorisation,
                0x02             : self._authorisation,
                'TAC_PLUS_ACCT'  : self._accounting,
                0x03             : self._accounting,
        }

        self.auth_type_mapper = {
                'TAC_PLUS_AUTHEN_TYPE_ASCII'   : self._auth_plain,
                0x01                           : self._auth_plain,
                'TAC_PLUS_AUTHEN_TYPE_PAP'     : self._auth_pap,
                0x02                           : self._auth_pap,
                'TAC_PLUS_AUTHEN_TYPE_CHAP'    : self._auth_chap,
                0x03                           : self._auth_chap,
                'TAC_PLUS_AUTHEN_TYPE_MSCHAP'  : self._auth_mschap,
                0x04                           : self._auth_mschap,
                'TAC_PLUS_AUTHEN_TYPE_MSCHAPV2': self._auth_mschapv2,
                0x05                           : self._auth_mschapv2,
        }


    def _auth_plain(self, rx_header, rx_body):
        """Process ascii authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        self._authen_reply_error(rx_header, rx_body)


    def _auth_pap(self, rx_header, rx_body):
        """Process pap authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        self._authen_reply_error(rx_header, rx_body)


    def _auth_chap(self, rx_header, rx_body):
        """Process chap authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        self._authen_reply_error(rx_header, rx_body)


    def _auth_mschap(self, rx_header, rx_body):
        """Process mschap authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        self._authen_reply_error(rx_header, rx_body)


    def _auth_mschapv2(self, rx_header, rx_body):
        """Process mschapv2 authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        self._authen_reply_error(rx_header, rx_body)


    def _authen_reply_error(self, rx_header, rx_body):
        """Process mschapv2 authentication

        Args:
          rx_header(obj): dataclass containing header fields
          rx_body(obj): dataclass containing body fields
        Exceptions:
          None
        Returns:
          None
        """

        # Build reply packet header
        seq_no = rx_header.sequence_no + 1
        tx_header = Header(HeaderFields(rx_header.version,
                                        flags.TAC_PLUS_AUTHEN,
                                        rx_header.session_id, 0), seq_no)

        # Build the error reply packet body
        fields = AuthenReplyFields(flags.TAC_PLUS_AUTHEN_STATUS_ERROR, 0,
                                   'Functionality NOT implemented')
        reply = AuthenReplyPacket(tx_header, fields=fields,
                                  secret=self.shared_secret)

        # Write your packet to the transport layer
        self.transport.write(bytes(reply))


    def _authentication(self, rx_header, raw_body):
        """Process authentication packets

        Args:
          rx_header(dict): header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # Determine the type of packet to process
        # AuthenSTART
        if rx_header.sequence_no == 1:
            pkt = AuthenStartPacket(rx_header, raw_body, secret='test')
            rx_body_fields = pkt.decode

            # Use function mapper dict to decide how we handle the packet
            self.auth_type_mapper[rx_body_fields.authen_type](rx_header,
                                                              rx_body_fields)

        # AuthenCONTINUE
        else:
            print('authen continue')


    def _authorisation(self, rx_header, raw_body):
        """Process authorisation packets

        Args:
          rx_header(dict): header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # TAC_PLUS_AUTHOR_STATUS_ERROR
        # Determine the type of packet to process
        if rx_header.sequence_no == 1:
            print('author request')
        else:
            print('author response')


    def _accounting(self, rx_header, raw_body):
        """Process accounting packets

        Args:
          rx_header(dict): header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        # TAC_PLUS_ACCT_STATUS_ERROR
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

        ip_address = self.transport.getPeer().host
        self.shared_secret = self.factory.get_shared_secret(ip_address)

        # Decode the TACACS+ packet header
        raw = six.BytesIO(data)
        rx_header = Header.decode(raw.read(12))

        # Use function mapper dict to decide how we handle the packet
        self.packet_type_mapper[rx_header.packet_type](rx_header, raw.read())


class TACACSPlusFactory(protocol.Factory):
    """Class providing the TACACS+ factory"""

    protocol = TACACSPlusProtocol

    def get_shared_secret(self, ip):
        """Lookup the client shared secret value from the clients ip address

        Args:
          ip(str): containing clients ip address
        Exceptions:
          None
        Returns
          secret(str): containing the shared secret key
        """

        secrets = { '127.0.0.1': 'test' }

        try:
            return secrets[ip]
        except KeyError as e:
            log.debug('wibble {0}'.format(str(e)))
            return ''


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

        credentials = { 'test': 'test' }

        try:
            if credentials[username] == password:
                return True
        except KeyError as e:
            log.debug('wibble {0}'.format(str(e)))

        return False


if __name__ == "__main__":
    reactor.listenTCP(4949, TACACSPlusFactory())
    print("TACACS+ server listening on port 4949...")
    reactor.run()
