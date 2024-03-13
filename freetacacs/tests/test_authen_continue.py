"""
Module provides unit tests for the Authentication Continue class

Classes:
    TestAuthenContinueFields
    TestAuthenContinue

Functions:
    None
"""

import six
import pytest
from twisted.trial import unittest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import AuthenContinueFields
from freetacacs.authentication import TACACSPlusAuthenContinue as AuthenContPacket


class TestAuthenContinueFields(unittest.TestCase):
    """Test class for testing the Authentication Continue Fields class"""

    def test_invalid_flags(self):
        """Test we handle passing a invalid flags field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags='invalid',
                                          user_msg='test', data='test')

        assert str(e.value) == 'Flags should be of type int'


    def test_invalid_user_msg(self):
        """Test we handle passing a invalid user_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags=0x00,
                                          user_msg=0, data='test')

        assert str(e.value) == 'User Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags=0x00,
                                          user_msg='test', data=0)

        assert str(e.value) == 'Data should be of type string'


    def test_default_authentication_continue_fields_string(self):
        """Test we can get the default string representation of authentication continue fields"""

        fields = AuthenContinueFields()

        assert str(fields) == 'flags: TAC_PLUS_CONTINUE_FLAG_ABORT, user_msg: , data: '


    def test_default_authentication_continue_fields_dict(self):
        """Test we can get the default dict representation of authentication continue fields"""

        fields = AuthenContinueFields()

        assert vars(fields) == {
                                 'flags'    : 0x01,
                                 'user_msg' : '',
                                 'data'     : '',
                                }


    def test_authentication_continue_fields_string(self):
        """Test we can get the string representation of authentication continue fields"""

        fields = AuthenContinueFields(flags=0x00,
                                      user_msg='Functionality NOT implemented',
                                      data='Functionality NOT implemented')

        assert str(fields) == 'flags: 0, user_msg: Functionality NOT implemented,' \
                              ' data: Functionality NOT implemented'


    def test_accounting_reply_fields_dict(self):
        """Test we can get the default dict representation of authentication continue fields"""

        fields = AuthenContinueFields(flags=0x00,
                                      user_msg='Functionality NOT implemented',
                                      data='Functionality NOT implemented')

        assert vars(fields) == {
                                 'flags'    : 0,
                                 'user_msg' : 'Functionality NOT implemented',
                                 'data'     : 'Functionality NOT implemented',
                                }


class TestAuthenContinuePacket(unittest.TestCase):
    """Test class for testing the Authentication Continue class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAuthenContinue class"""

        raw_pkt = b'\xc1\x03\x01\x00\x9c7<$\x00\x00\x00?\xa2\x11\xe3\xad\x93\xb9\x1ezZ\xaa\xf7(d"\xb35/q\x92\xd7D\x8f\r\xc5X#A\xd9\x16\x86\x84\x00a\xcb\xbeL\x0cRvz>[]\x7f\xd1\\\xe4\xfc`\x17~\xcb\xcb\x18\x150\xe0\xbaw\x0bN"\xc7'

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572

        # What should be returned when we call __str__ on object
        required_str = 'user_msg_len: 29, data_len: 29, flags: 0,' \
                       ' user_msg: Functionality NOT implemented,' \
                       ' data: Functionality NOT implemented'

        # Configure the header
        header = Header(HeaderFields(version=version,
                                     packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Accounting request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenContPacket(header, body=raw.read(), secret='test')

        fields = pkt.decode

        assert isinstance(pkt, AuthenContPacket)
        assert fields.flags == 0
        assert fields.user_msg == 'Functionality NOT implemented'
        assert fields.data == 'Functionality NOT implemented'
        assert pkt.length == 63
        assert str(pkt) == required_str


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthenContinue class"""

        version = 193
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 2620865572

        # Configure the header
        header = Header(HeaderFields(version=version,
                                     packet_type=packet_type,
                                     session_id=session_id))

        fields = AuthenContinueFields(user_msg='Functionality NOT implemented',
                                 data='Functionality NOT implemented',
                                 flags=0x00)

        pkt = AuthenContPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthenContPacket)
        assert str(pkt) == 'user_msg_len: 29, data_len: 29, flags: 0,' \
                           ' user_msg: Functionality NOT implemented,' \
                           ' data: Functionality NOT implemented'
        assert bytes(pkt) == b'\xc1\x03\x01\x00\x9c7<$\x00\x00\x00?\xa2\x11\xe3\xad\x93\xb9\x1ezZ\xaa\xf7(d"\xb35/q\x92\xd7D\x8f\r\xc5X#A\xd9\x16\x86\x84\x00a\xcb\xbeL\x0cRvz>[]\x7f\xd1\\\xe4\xfc`\x17~\xcb\xcb\x18\x150\xe0\xbaw\x0bN"\xc7'


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b'\xc1\x03\x01\x00\x9c7<$\x00\x00\x00?\xa2\x11\xe3\xad\x93\xb9\x1ezZ\xaa\xf7(d"\xb35/q\x92\xd7D\x8f\r\xc5X#A\xd9\x16\x86\x84\x00a\xcb\xbeL\x0cRvz>[]\x7f\xd1\\\xe4\xfc`\x17~\xcb\xcb\x18\x150\xe0\xbaw\x0bN"\xc7'

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 1

        # Configure the header
        header = Header(HeaderFields(version=version,
                                     packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenContPacket(header, body=raw.read(), secret='test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenContinue packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b'\xc1\x03\x01\x00\x9c7<$\x00\x00\x00?\xa2\x11\xe3\xad\x93\xb9\x1ezZ\xaa\xf7(d"\xb35/q\x92\xd7D\x8f\r\xc5X#A\xd9\x16\x86\x84\x00a\xcb\xbeL\x0cRvz>[]\x7f\xd1\\\xe4\xfc`\x17~\xcb\xcb\x18\x150\xe0\xbaw\x0bN"\xc7'

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572

        # Configure the header
        header = Header(HeaderFields(version=version,
                                     packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenContPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenContinue packet. TACACS+' \
                               ' client/server shared key probably does not match'
