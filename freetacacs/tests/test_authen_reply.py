"""
Module provides unit tests for the Authentication Reply class

Classes:
    TestAuthenReplyFields
    TestAuthenReply

Functions:
    None
"""

import six
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import AuthenReplyFields
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReplyPacket

class TestAuthenReplyFields:
    """Test class for testing the Authentication Reply Fields class"""


    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenReplyFields(status='invalid', flags=0x00,
                                       server_msg='test', data='test')

        assert str(e.value) == 'Status should be of type int'


    def test_invalid_flags(self):
        """Test we handle passing a invalid flags field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenReplyFields(status=0, flags='invalid',
                                       server_msg='test', data='test')

        assert str(e.value) == 'Flags should be of type int'


    def test_invalid_server_msg(self):
        """Test we handle passing a invalid server_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenReplyFields(status=0x00, flags=0x00,
                                      server_msg=0, data='test')

        assert str(e.value) == 'Server Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenReplyFields(status=0x00, flags=0x00,
                                      server_msg='test', data=0)

        assert str(e.value) == 'Data should be of type string'


    def test_authen_reply_fields_string(self):
        """Test we can get a string representation of authen reply fields"""

        fields = AuthenReplyFields(status=0x01, flags=0x01,
                                   server_msg='test', data='test')

        assert str(fields) == 'status: TAC_PLUS_AUTHEN_STATUS_PASS,' \
                              ' flags: TAC_PLUS_REPLY_FLAG_NOECHO,' \
                              ' server_msg: test, data: test'


    def test_authen_reply_fields_dict(self):
        """Test we can get a dict representation of authen reply fields"""

        fields = AuthenReplyFields(status=0x00, flags=0x00,
                                   server_msg='test', data='test')

        assert vars(fields) == {'status': 0, 'flags': 0, 'server_msg': 'test',
                                'data': 'test'}


class TestAuthenReply:
    """Test class for testing the Authentication Reply class"""


    def test_create_instance_without_body_nor_fields(self):
        """Test we handle failure to pass either body for fields"""

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        with pytest.raises(TypeError) as e:
            AuthenReplyPacket(header, fields=AuthenReplyFields(), secret='test')

        assert str(e.value) == "__init__() missing 2 required positional" \
                               " arguments: 'status' and 'flags'"


    def test_create_instance_with_body(self):
        """Test we can create an instance from TACACSPlusAuthenReply class"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication reply instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenReplyPacket(header, raw.read(), 'test')

        assert isinstance(pkt, AuthenReplyPacket)
        assert str(pkt) == 'status: None, flags: None, server_msg_len: None,' \
                           ' data_len: None, server_msg: None, data: None'


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthenReply class"""

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        fields = AuthenReplyFields(status=0x00, flags=0x00,
                                   server_msg='test', data='test')
        pkt = AuthenReplyPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthenReplyPacket)
        assert str(pkt) == 'status: 0, flags: 0, server_msg_len: 4,' \
                           ' data_len: 4, server_msg: test, data: test'
