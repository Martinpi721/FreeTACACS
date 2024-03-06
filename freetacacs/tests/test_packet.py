"""
Module provides unit tests for the packet module

Classes:
    TestRequestFields
    TestReplyFields
    TestTACACSPlusPacket

Functions:
    None
"""

import pytest
from twisted.trial import unittest
import six

# Import code to be tested
from freetacacs.flags import TAC_PLUS_AUTHEN
from freetacacs.packet import TACACSPlusPacket as Packet
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header

from freetacacs.packet import RequestFields, ReplyFields


class TestRequestFields(unittest.TestCase):
    """Test class for testing the Request Fields class"""

    def test_invalid_priv_lvl(self):
        """Test we handle passing a invalid privilege level field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(priv_lvl='invalid')

        assert str(e.value) == 'Privilege Level should be of type int'


    def test_invalid_authen_type(self):
        """Test we handle passing a invalid authentication method field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(authen_type='invalid')

        assert str(e.value) == 'Authentication Type should be of type int'


    def test_invalid_authen_service(self):
        """Test we handle passing a invalid authentication service type field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(authen_service='invalid')

        assert str(e.value) == 'Authentication Service should be of type int'


    def test_invalid_user(self):
        """Test we handle passing a invalid user field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(user=123)

        assert str(e.value) == 'User should be of type string'


    def test_invalid_port(self):
        """Test we handle passing a invalid port field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(port=123)

        assert str(e.value) == 'Port should be of type string'


    def test_invalid_remote_address(self):
        """Test we handle passing a invalid remote address field type"""

        with pytest.raises(TypeError) as e:
            fields = RequestFields(remote_address=123)

        assert str(e.value) == 'Remote Address should be of type string'


class TestReplyFields(unittest.TestCase):
    """Test class for testing the Reply Fields class"""

    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        with pytest.raises(TypeError) as e:
            fields = ReplyFields(status='invalid')

        assert str(e.value) == 'Status should be of type int'


    def test_invalid_server_message(self):
        """Test we handle passing a invalid server_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = ReplyFields(server_msg=1)

        assert str(e.value) == 'Server Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = ReplyFields(data=1)

        assert str(e.value) == 'Data should be of type string'



class TestTACACSPlusPacket:
    """Test class for testing the packet module"""

    def test_create_instance(self):
        """Test we can create a instance of TACACSPlusPacket class"""

        version = 193
        packet_type = TAC_PLUS_AUTHEN
        session_id = 1932205026
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        raw = six.BytesIO(b'TACACS+ data body')
        pkt = Packet(header, raw.read(), 'test')

        assert isinstance(pkt, Packet)


    def test_deobfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.deobfuscate == b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'


    def test_obfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_plain_body = b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'

        version = 193
        packet_type = TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_plain_body)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.obfuscate == b"\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"


    def test_length_of_packet_body(self):
        """Test we can get the length packet bodies"""

        raw_plain_body = b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'

        version = 193
        packet_type = TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_plain_body)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.length == 40


    def test_convert_packet_body_to_bytes(self):
        """Test we can convert packet bodies to byte format"""

        raw_plain_body = b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'

        version = 193
        packet_type = TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_plain_body)
        pkt = Packet(header, raw.read(), 'test')

        assert bytes(pkt) == b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"
