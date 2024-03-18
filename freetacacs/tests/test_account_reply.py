"""
Module provides unit tests for the Accounting Reply class

Classes:
    TestAcctReplyFields
    TestAcctReply

Functions:
    None
"""

import six
import pytest
from twisted.trial import unittest
from twisted.logger import LogLevel, capturedLogs

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.accounting import AcctReplyFields
from freetacacs.accounting import TACACSPlusAccountReply as AcctReplyPacket


class TestAcctReplyFields(unittest.TestCase):
    """Test class for testing the Accounting reply Fields class"""

    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status='invalid')

        assert str(e.value) == 'Status should be of type int'


    def test_invalid_server_message(self):
        """Test we handle passing a invalid server_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       server_msg=1)

        assert str(e.value) == 'Server Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       data=1)

        assert str(e.value) == 'Data should be of type string'


    def test_default_accounting_reply_fields_string(self):
        """Test we can get the default string representation of accounting reply fields"""

        fields = AcctReplyFields()

        assert str(fields) == 'status: TAC_PLUS_ACCT_STATUS_SUCCESS, server_msg: , data: '


    def test_default_accounting_reply_fields_dict(self):
        """Test we can get the default dict representation of accounting reply fields"""

        fields = AcctReplyFields()

        assert vars(fields) == {
                                 'status'     : 1,
                                 'server_msg' : '',
                                 'data'       : '',
                                }


class TestAcctReply(unittest.TestCase):
    """Test class for testing the Accounting Reply class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAccountRequest class"""

        raw_pkt = b'\xc0\x03\x01\x00\x01\xaf\x137\x00\x00\x00?\xe2\x96\xa0a\xdax\xe3\x97b\xe8[$\xf51\xa4\x8b\xfb\xb15)LV\xfec\xe4+G\x10\x1bW\xd9\x9ecrYm9\x869!\x8a\xfcFM\xf8\xe8\xd5.\xfd\x0e9*\xa5\xe1\xd2\xf2\x17Y>\xf5\xc7\x89N'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 28250935

        # What should be returned when we call __str__ on object
        required_str = 'server_msg_len: 29, data_len: 29, status: 2,' \
                       ' server_msg: Functionality NOT implemented,' \
                       ' data: Functionality NOT implemented'

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Accounting request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctReplyPacket(header, body=raw.read(), secret='test')

        fields = pkt.decode

        assert isinstance(pkt, AcctReplyPacket)
        assert fields.status == 2
        assert fields.server_msg == 'Functionality NOT implemented'
        assert fields.data == 'Functionality NOT implemented'
        assert pkt.length == 63
        assert str(pkt) == required_str


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAcctReply class"""

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 2620865572

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        fields = AcctReplyFields(server_msg='Functionality NOT implemented',
                                 data='Functionality NOT implemented',
                                 status=flags.TAC_PLUS_ACCT_STATUS_ERROR)

        pkt = AcctReplyPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AcctReplyPacket)
        assert str(pkt) == 'server_msg_len: 29, data_len: 29, status: 2,' \
                           ' server_msg: Functionality NOT implemented,' \
                           ' data: Functionality NOT implemented'
        assert bytes(pkt) == b'\xc0\x03\x01\x00\x9c7<$\x00\x00\x00?\x83\xb0\xf7\xd2\xcbc\x9c\xff\xca(\xbf&2d\xd9@\xa7\xd8\xad\xaa\xa0\xc7\x88\xc5CO\x98\xe5\xc0\xb7\xe9}\xaa\x9c\xf4+5\xe6m\xa7FC;\x7f\x15r\xf7?K\x89\x04\x13\xab\x85\xb4\x94\xa4\xf9\x04u\xcf\x19\xf0'


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b'\xc0\x03\x01\x00\x01\xaf\x137\x00\x00\x00?\xe2\x96\xa0a\xdax\xe3\x97b\xe8[$\xf51\xa4\x8b\xfb\xb15)LV\xfec\xe4+G\x10\x1bW\xd9\x9ecrYm9\x869!\x8a\xfcFM\xf8\xe8\xd5.\xfd\x0e9*\xa5\xe1\xd2\xf2\x17Y>\xf5\xc7\x89N'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 1

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctReplyPacket(header, body=raw.read(), secret='test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AcctReply packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b'\xc0\x03\x01\x00\x01\xaf\x137\x00\x00\x00?\xe2\x96\xa0a\xdax\xe3\x97b\xe8[$\xf51\xa4\x8b\xfb\xb15)LV\xfec\xe4+G\x10\x1bW\xd9\x9ecrYm9\x869!\x8a\xfcFM\xf8\xe8\xd5.\xfd\x0e9*\xa5\xe1\xd2\xf2\x17Y>\xf5\xc7\x89N'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 2620865572

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctReplyPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AcctReply packet. TACACS+' \
                               ' client/server shared key probably does not match'
