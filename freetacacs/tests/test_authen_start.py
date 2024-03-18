"""
Module provides unit tests for the Authentication Start class

Classes:
    TestAuthenStartFields
    TestAuthenStart

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
from freetacacs.authentication import AuthenStartFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStartPacket


class TestAuthenStartFields(unittest.TestCase):
    """Test class for testing the Authentication Start Fields class"""

    def setUp(self):
        """Setup for all tests"""

        self._version = (flags.TAC_PLUS_MAJOR_VER * 0x10) + flags.TAC_PLUS_MINOR_VER
        self._auth_version = self._version + flags.TAC_PLUS_MINOR_VER_ONE


    def test_invalid_action(self):
        """Test we handle passing a invalid action field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(action='invalid')

        assert str(e.value) == 'Action should be of type int'


    def test_invalid_priv_lvl(self):
        """Test we handle passing a invalid priv_lvl field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(priv_lvl='invalid')

        assert str(e.value) == 'Privilege Level should be of type int'


    def test_invalid_authentication_type(self):
        """Test we handle passing a invalid authentication type field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(authen_type='invalid')

        assert str(e.value) == 'Authentication Type should be of type int'


    def test_invalid_authen_service(self):
        """Test we handle passing a invalid authentication service field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(authen_service='invalid')

        assert str(e.value) == 'Authentication Service should be of type int'


    def test_invalid_user(self):
        """Test we handle passing a invalid user field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(user=1234)

        assert str(e.value) == 'User should be of type string'


    def test_invalid_port(self):
        """Test we handle passing a invalid port field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(port=1234)

        assert str(e.value) == 'Port should be of type string'


    def test_invalid_remote_Address(self):
        """Test we handle passing a invalid remote address field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(remote_address=1234)

        assert str(e.value) == 'Remote Address should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=123456,
                                     length=40))

        with pytest.raises(TypeError) as e:
            fields = AuthenStartFields(data=1234)

        assert str(e.value) == 'Data should be of type string'


    def test_authen_start_fields_string(self):
        """Test we can get a string representation of authen start fields"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572,
                                     length=40))

        fields = AuthenStartFields(action=1, priv_lvl=1, authen_type=1, authen_service=1,
                                   user='test', port='1234', remote_address='test',
                                   data='testing123')

        assert str(fields) == 'action: TAC_PLUS_AUTHEN_LOGIN,' \
                              ' priv_lvl: TAC_PLUS_PRIV_LVL_USER,' \
                              ' authen_type: TAC_PLUS_AUTHEN_TYPE_ASCII,' \
                              ' authen_service: TAC_PLUS_AUTHEN_SVC_LOGIN,' \
                              ' user: test, port: 1234, remote_address: test,' \
                              ' data: testing123'


    def test_authen_start_fields_dict(self):
        """Test we can get a dict representation of authen start fields"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572,
                                     length=40))

        fields = AuthenStartFields(action=1, priv_lvl=1, authen_type=1, authen_service=1,
                                   user='test', port='1234', remote_address='test',
                                   data='testing123')

        assert vars(fields) == {'action': 1, 'priv_lvl': 1, 'authen_type': 1,
                                'authen_service': 1, 'user': 'test', 'port': '1234',
                                'remote_address': 'test', 'data': 'testing123'}


class TestAuthenStart(unittest.TestCase):
    """Test class for testing the Authentication Start class"""

    def setUp(self):
        """Setup for all tests"""

        self._version = (flags.TAC_PLUS_MAJOR_VER * 0x10) + flags.TAC_PLUS_MINOR_VER
        self._auth_version = self._version + flags.TAC_PLUS_MINOR_VER_ONE


    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAuthenStart class"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # What should be returned when we call __str__ on object
        required_str = 'action: 1, priv_lvl:' \
                ' 0, authen_type: 2,' \
                ' authen_service: 1, user_len: 4, port_len: 11,' \
                ' rem_addr_len: 13, data_len: 4, user: test, port: python_tty0,' \
                ' rem_addr: python_device, data: test'

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, body=raw.read(), secret='test')

        fields = pkt.decode

        assert isinstance(pkt, AuthenStartPacket)
        assert fields.action == 1
        assert fields.priv_lvl == 0
        assert fields.authen_type == 2
        assert fields.authen_service == 1
        assert fields.user == 'test'
        assert fields.port == 'python_tty0'
        assert fields.remote_address == 'python_device'
        assert fields.data == 'test'
        assert pkt.length == 40
        assert str(pkt) == required_str


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthenStart class"""

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572))

        fields = AuthenStartFields(action=flags.TAC_PLUS_AUTHEN_LOGIN,
                                   priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                   authen_type=flags.TAC_PLUS_AUTHEN_TYPE_PAP,
                                   authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                   user='jsmith',
                                   port='python_tty0',
                                   remote_address='python_device',
                                   data='top_secret'
                                  )
        pkt = AuthenStartPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthenStartPacket)
        assert str(pkt) == 'action: 1, priv_lvl: 0, authen_type: 2, authen_service: 1,' \
                           ' user_len: 6, port_len: 11, rem_addr_len: 13,' \
                           ' data_len: 10, user: jsmith, port: python_tty0,' \
                           ' rem_addr: python_device, data: top_secret'
        assert bytes(pkt) == b'\xc1\x01\x01\x00\x9c7<$\x00\x00\x000\xa3\x0c\xe1\xb1\x95\xf4f\x1eS\xad\xf3.~+\xaf%/`\xdd\xf7T\xafY\xd5\x05#T\xc8\x13\x8c\x84+`\xca\x8eP\x01Tv|!jOv\xdbZ\xf8\xa8'


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=1))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, body=raw.read(), secret='test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenStart packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_mismatch(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenStart packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # Configure the header
        header = Header(HeaderFields(version=self._auth_version,
                                     packet_type=flags.TAC_PLUS_AUTHEN,
                                     session_id=2620865572))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, raw.read())

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenStart packet. TACACS+' \
                               ' client/server shared key probably does not match'
