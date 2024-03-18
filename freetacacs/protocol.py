"""
Module implements the TACACSPlusProtocl class

Classes:
    TACACSPlusProtocol

Functions:
    catch_error
"""

from twisted.internet import protocol
from twisted.logger import Logger
import six

# Local imports
from freetacacs import flags
from freetacacs.misc import create_log_dict
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
# Authentication
from freetacacs.authentication import AuthenReplyFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStartPacket
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReplyPacket
# Authorisation
from freetacacs.authorisation import AuthorReplyFields
from freetacacs.authorisation import TACACSPlusAuthorRequest as AuthorRequestPacket
from freetacacs.authorisation import TACACSPlusAuthorReply as AuthorReplyPacket
# Accounting
from freetacacs.accounting import AcctReplyFields
from freetacacs.accounting import TACACSPlusAccountRequest as AcctRequestPacket
from freetacacs.accounting import TACACSPlusAccountReply as AcctReplyPacket

def catch_error(err):
    print(err)
    return "Internal error in server"


class TACACSPlusProtocol(protocol.Protocol):
    """Define the TACACS+ protocol"""

    log = Logger()

    def __init__(self):
        """Create mapper dictionaries

        Args:
          None
        Exceptions:
          None
        Returns:
          None
        """

        # Client connection details
        self._nas_ip = None
        self._nas_port = None
        self._server_ip = None
        self._server_port = None

        self._packet_type_mapper = {
                'TAC_PLUS_AUTHEN': self._authentication,
                0x01             : self._authentication,
                'TAC_PLUS_AUTHOR': self._authorisation,
                0x02             : self._authorisation,
                'TAC_PLUS_ACCT'  : self._accounting,
                0x03             : self._accounting,
        }

        self._auth_type_mapper = {
                'TAC_PLUS_AUTHEN_TYPE_ASCII'   : self._auth_ascii,
                0x01                           : self._auth_ascii,
                'TAC_PLUS_AUTHEN_TYPE_PAP'     : self._auth_pap,
                0x02                           : self._auth_pap,
                'TAC_PLUS_AUTHEN_TYPE_CHAP'    : self._auth_chap,
                0x03                           : self._auth_chap,
                'TAC_PLUS_AUTHEN_TYPE_MSCHAP'  : self._auth_mschap,
                0x04                           : self._auth_mschap,
                'TAC_PLUS_AUTHEN_TYPE_MSCHAPV2': self._auth_mschapv2,
                0x05                           : self._auth_mschapv2,
        }


    def _auth_ascii(self, rx_header_fields, rx_body_fields, shared_secret):
        """Process ascii authentication

        Args:
          rx_header_fields(obj): dataclass containing header fields
          rx_body_fields(obj): dataclass containing body fields
          shared_secret(str): containing the TACACS+ shared secret
        Exceptions:
          None
        Returns:
          None
        """

        def send_response(value):
            """Create a TACACS+ response packet and write it to the network transport

            Args:
              value(bool): user credentials are valid/invalid [True|False]
            Exceptions:
              None
            Returns:
              None
            """

            authenticated = value

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHEN,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthenReplyFields(status=flags.TAC_PLUS_AUTHEN_STATUS_ERROR,
                                               flags=flags.TAC_PLUS_REPLY_FLAG_NOTSET,
                                               server_msg='Functionality NOT implemented')

            reply = AuthenReplyPacket(tx_header, fields=tx_body_fields, secret=value)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)


        # Check the sequence no. a client sequence no. should always be odd
        # meaning any response must be even. In addition the max sequence no.
        # to meet the RFC specification is 255.
        if rx_header_fields.sequence_no % 2 == 0:
            self.transport.loseConnection()
            return

        if rx_header_fields.sequence_no > 255:
            self.transport.loseConnection()
            return

        # Create a request debug logging message
        kwargs = create_log_dict(rx_header_fields, rx_body_fields)
        kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                            str(rx_body_fields)]))
        self.log.debug(kwargs['text'], **kwargs)

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(send_response)
        d.addErrback(catch_error)


    def _auth_pap(self, rx_header_fields, rx_body_fields, shared_secret):
        """Process pap authentication

        Args:
          rx_header_fields(obj): dataclass containing header fields
          rx_body_fields(obj): dataclass containing body fields
          shared_secret(str): containing the TACACS+ shared secret
        Exceptions:
          None
        Returns:
          None
        """

        def send_response(value):
            """Create a TACACS+ response packet and write it to the network transport

            Args:
              value(bool): user credentials are valid/invalid [True|False]
            Exceptions:
              None
            Returns:
              None
            """

            authenticated = value

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHEN,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthenReplyFields(status=flags.TAC_PLUS_AUTHEN_STATUS_ERROR,
                                               flags=flags.TAC_PLUS_REPLY_FLAG_NOTSET,
                                               server_msg='Functionality NOT implemented')

            reply = AuthenReplyPacket(tx_header, fields=tx_body_fields,
                                      secret=shared_secret)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)


        # Create a request debug logging message
        kwargs = create_log_dict(rx_header_fields, rx_body_fields)
        kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                            str(rx_body_fields)]))
        self.log.debug(kwargs['text'], **kwargs)

        # Validate the users credentials via the deferred
        d = self.factory.valid_credentials(rx_body_fields.user,
                                           rx_body_fields.data)
        d.addCallback(send_response)
        d.addErrback(catch_error)


    def _auth_chap(self, rx_header_fields, rx_body_fields, shared_secret):
        """Process chap authentication

        Args:
          rx_header_fields(obj): dataclass containing header fields
          rx_body_fields(obj): dataclass containing body fields
          shared_secret(str): containing the TACACS+ shared secret
        Exceptions:
          None
        Returns:
          None
        """

        def send_response(value):
            """Create a TACACS+ response packet and write it to the network transport

            Args:
              value(bool): user credentials are valid/invalid [True|False]
            Exceptions:
              None
            Returns:
              None
            """

            authenticated = value

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHEN,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthenReplyFields(status=flags.TAC_PLUS_AUTHEN_STATUS_ERROR,
                                               flags=flags.TAC_PLUS_REPLY_FLAG_NOTSET,
                                               server_msg='Functionality NOT implemented')

            reply = AuthenReplyPacket(tx_header, fields=tx_body_fields, secret=value)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)


        # Create a request debug logging message
        kwargs = create_log_dict(rx_header_fields, rx_body_fields)
        kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                            str(rx_body_fields)]))
        self.log.debug(kwargs['text'], **kwargs)

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(send_response)
        d.addErrback(catch_error)


    def _auth_mschap(self, rx_header_fields, rx_body_fields, shared_secret):
        """Process mschap authentication

        Args:
          rx_header_fields(obj): dataclass containing header fields
          rx_body_fields(obj): dataclass containing body fields
          shared_secret(str): containing the TACACS+ shared secret
        Exceptions:
          None
        Returns:
          None
        """

        def send_response(value):
            """Create a TACACS+ response packet and write it to the network transport

            Args:
              value(bool): user credentials are valid/invalid [True|False]
            Exceptions:
              None
            Returns:
              None
            """

            authenticated = value

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHEN,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthenReplyFields(status=flags.TAC_PLUS_AUTHEN_STATUS_ERROR,
                                               flags=flags.TAC_PLUS_REPLY_FLAG_NOTSET,
                                               server_msg='Functionality NOT implemented')

            reply = AuthenReplyPacket(tx_header, fields=tx_body_fields, secret=value)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)


        # Create a request debug logging message
        kwargs = create_log_dict(rx_header_fields, rx_body_fields)
        kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                            str(rx_body_fields)]))
        self.log.debug(kwargs['text'], **kwargs)

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(send_response)
        d.addErrback(catch_error)


    def _auth_mschapv2(self, rx_header_fields, rx_body_fields, shared_secret):
        """Process mschapv2 authentication

        Args:
          rx_header_fields(obj): dataclass containing header fields
          rx_body_fields(obj): dataclass containing body fields
          shared_secret(str): containing the TACACS+ shared secret
        Exceptions:
          None
        Returns:
          None
        """

        def send_response(value):
            """Create a TACACS+ response packet and write it to the network transport

            Args:
              value(bool): user credentials are valid/invalid [True|False]
            Exceptions:
              None
            Returns:
              None
            """

            authenticated = value

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHEN,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthenReplyFields(status=flags.TAC_PLUS_AUTHEN_STATUS_ERROR,
                                               flags=flags.TAC_PLUS_REPLY_FLAG_NOTSET,
                                               server_msg='Functionality NOT implemented')

            reply = AuthenReplyPacket(tx_header, fields=tx_body_fields, secret=value)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)

        # Create a request debug logging message
        kwargs = create_log_dict(rx_header_fields, rx_body_fields)
        kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                            str(rx_body_fields)]))
        self.log.debug(kwargs['text'], **kwargs)

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(send_response)
        d.addErrback(catch_error)


    def _authentication(self, rx_header_fields, raw_body):
        """Process authentication packets

        Args:
          rx_header_fields(obj): dataclass containing header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        def decode_packet(value):
            """Process authentication packets

            Args:
              value(str): containing the TACACS+ shared secret
            Exceptions:
              None
            Returns:
              None
            """

            shared_secret = value

            # Determine the type of packet to process
            # AuthenSTART
            if rx_header_fields.sequence_no == 1:
                pkt = AuthenStartPacket(rx_header_fields, body=raw_body,
                                        secret=shared_secret)
                rx_body_fields = pkt.decode

                # Use function mapper dict to decide how we handle the packet
                self._auth_type_mapper[rx_body_fields.authen_type](rx_header_fields,
                                                                   rx_body_fields,
                                                                   shared_secret)

            # AuthenCONTINUE
            else:
                print('authen continue')


        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(decode_packet)
        d.addErrback(catch_error)


    def _authorisation(self, rx_header_fields, raw_body):
        """Process authorisation packets

        Args:
          rx_header_fields(obj): dataclass containing header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        def decode_packet(value):
            """Process authorisation packets

            Args:
              value(str): containing the TACACS+ shared secret
            Exceptions:
              None
            Returns:
              None
            """

            shared_secret = value

            pkt = AuthorRequestPacket(rx_header_fields, body=raw_body,
                                      secret=shared_secret)
            rx_body_fields = pkt.decode

            # Create a request debug logging message
            kwargs = create_log_dict(rx_header_fields, rx_body_fields)
            kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                                str(rx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_AUTHOR,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_ERROR,
                                               arg_cnt=0,
                                               server_msg='Functionality NOT implemented',
                                               data='Functionality NOT implemented',
                                               args=[])

            reply = AuthorReplyPacket(tx_header, fields=tx_body_fields,
                                      secret=shared_secret)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(decode_packet)
        d.addErrback(catch_error)


    def _accounting(self, rx_header_fields, raw_body):
        """Process accounting packets

        Args:
          rx_header_fields(obj): dataclass containing header fields
          raw_body(byte): packet body
        Exceptions:
          None
        Returns:
          None
        """

        def decode_packet(value):
            """Process accounting packets

            Args:
              value(str): containing the TACACS+ shared secret
            Exceptions:
              None
            Returns:
              None
            """

            shared_secret = value

            pkt = AcctRequestPacket(rx_header_fields, body=raw_body,
                                    secret=shared_secret)
            rx_body_fields = pkt.decode

            # Create a request debug logging message
            kwargs = create_log_dict(rx_header_fields, rx_body_fields)
            kwargs['text'] = 'rx packet <{0}>'.format(' '.join([str(rx_header_fields),
                                                                str(rx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)

            # Build reply packet header
            tx_header_fields = HeaderFields(version=rx_header_fields.version,
                                            packet_type=flags.TAC_PLUS_ACCT,
                                            session_id=rx_header_fields.session_id,
                                            sequence_no=rx_header_fields.sequence_no + 1)

            tx_header = Header(tx_header_fields)

            # Build the reply packet body
            tx_body_fields = AcctReplyFields(status=flags.TAC_PLUS_ACCT_STATUS_ERROR,
                                               server_msg='Functionality NOT implemented',
                                               data='Functionality NOT implemented')

            reply = AcctReplyPacket(tx_header, fields=tx_body_fields,
                                    secret=shared_secret)

            # Create a response debug logging message
            tx_header_fields.length = reply.length
            kwargs = create_log_dict(tx_header_fields, tx_body_fields)
            kwargs['text'] = 'tx packet <{0}>'.format(' '.join([str(tx_header_fields),
                                                                str(tx_body_fields)]))
            self.log.debug(kwargs['text'], **kwargs)

            # Write your packet to the transport layer
            self.transport.write(bytes(reply))

        d = self.factory.get_shared_secret(self._nas_ip)
        d.addCallback(decode_packet)
        d.addErrback(catch_error)


    def connectionMade(self):
        """Called when a connection is made to the server instance

        Convienient time to collect some connection information

        Args:
          None
        Exceptions:
          None
        Returns
          None
        """

        # Get the local IP address
        self._server_ip = self.transport.getHost().host
        self._server_port = self.transport.getHost().port

        # Get the IP address of the connecting client
        self._nas_ip = self.transport.getPeer().host
        self._nas_port = self.transport.getPeer().port

        # Create a connection object
        self._conn  = {
                       'server_ip': self._server_ip,
                       'server_port': self._server_port,
                       'nas_ip': self._nas_ip,
                       'nas_port': self._nas_port,
                      }


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
        try:
            raw = six.BytesIO(data)
            rx_header = Header.decode(raw.read(12))
        # Packet isn't byte encoded
        except TypeError as e:
            msg = f'NAS {self._nas_ip}:{self._nas_port} connected to' \
                  f' {self._server_ip}:{self._server_port} sent a packet' \
                   ' that is not byte encoded. Closing connection.'

            kwargs = self._conn
            kwargs['session_id'] = ''
            kwargs['sequence_no'] = ''
            kwargs['text'] = msg
            self.log.error(msg, **kwargs)

            # Reset the connection
            self.transport.loseConnection()
            return

        # Packet byte encoded but not a TACACS+ packet
        except ValueError as e:
            msg = f'NAS {self._nas_ip}:{self._nas_port} connected to' \
                  f' {self._server_ip}:{self._server_port} sent a packet' \
                   ' with a header not meeting TACACS+ specifications.'\
                   ' Closing connection.'

            kwargs = self._conn
            kwargs['session_id'] = ''
            kwargs['sequence_no'] = ''
            kwargs['text'] = msg
            self.log.error(msg, **kwargs)

            # Reset the connection
            self.transport.loseConnection()
            return

        # Use function mapper dict to decide how we handle the packet
        try:
            self._packet_type_mapper[rx_header.packet_type](rx_header, raw.read())
        # Not a recognised TACACS+ packet type
        except KeyError as e:
            msg = f'NAS {self._nas_ip}:{self._nas_port} connected to' \
                  f' {self._server_ip}:{self._server_port} sent a packet' \
                   ' with a invalid header. Closing connection.'

            kwargs = self._conn
            kwargs.update(vars(rx_header))
            kwargs['text'] = msg
            self.log.error(msg, **kwargs)

            # Reset the connection
            self.transport.loseConnection()
            return
