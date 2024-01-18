"""
Module provides unit tests for the header module

Classes:
    TestTACACSPlusHeader

Functions:
    None
"""

import struct
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header

# Import exceptions

class TestTACACSPlusHeader:
    """Test class for testing the header module"""

    def test_create_instance(self):
        """Test we can create a instance of TACACSPlusHeader class"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length))

        assert isinstance(header, Header)
        assert header.encoded == b'\x01\x01\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_AUTHEN, session_id: 1,' \
                              ' length: 1, sequence_no: 1, flags: 0'


    def test_packet_type_lookups_authen(self):
        """Test we can create a header with TAC_PLUS_AUTHEN packet types"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length))

        assert header.encoded == b'\x01\x01\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_AUTHEN, session_id: 1,' \
                              ' length: 1, sequence_no: 1, flags: 0'


    def test_packet_type_lookups_author(self):
        """Test we can create a header with TAC_PLUS_AUTHOR packet types"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length))

        assert header.encoded == b'\x01\x02\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_AUTHOR, session_id: 1,' \
                              ' length: 1, sequence_no: 1, flags: 0'


    def test_packet_type_lookups_acct(self):
        """Test we can create a header with TAC_PLUS_ACCT packet types"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length))

        assert header.encoded == b'\x01\x03\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_ACCT, session_id: 1,' \
                              ' length: 1, sequence_no: 1, flags: 0'


    def test_realistic_header_information(self):
        """Test we can create a header with TAC_PLUS_AUTHEN packet types"""

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 1087845697
        length = 40
        header = Header(HeaderFields(version, packet_type, session_id, length))

        assert header.encoded == b'\xc1\x01\x01\x00@\xd75A\x00\x00\x00('
        assert str(header) == 'version: 193, type: TAC_PLUS_AUTHEN, session_id: 1087845697,' \
                              ' length: 40, sequence_no: 1, flags: 0'


    def test_set_sequence_no(self):
        """Test we can create a header with custom sequence_no"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length),
                        sequence_no=22)

        assert header.encoded == b'\x01\x01\x16\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_AUTHEN, session_id: 1,' \
                              ' length: 1, sequence_no: 22, flags: 0'


    def test_set_flags(self):
        """Test we can create a header with custom flags set"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        header = Header(HeaderFields(version, packet_type, session_id, length),
                       flags=flags.TAC_PLUS_UNENCRYPTED_FLAG)

        assert header.encoded == b'\x01\x01\x01\x01\x00\x00\x00\x01\x00\x00\x00\x01'
        assert str(header) == 'version: 1, type: TAC_PLUS_AUTHEN, session_id: 1,' \
                              ' length: 1, sequence_no: 1, flags: 1'


    def test_create_instance_invalid_version(self):
        """Test we can handle a invalid version no."""

        version = 'v0.1'
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length))

        assert str(e.value) == 'Version should be of type int'


    def test_create_instance_invalid_packet_type(self):
        """Test we can handle a invalid packet type"""

        version = 0x01
        packet_type = 'auth'
        session_id = 0x01
        length = 1

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length))

        assert str(e.value) == 'Packet Type should be of type int'


    def test_create_instance_invalid_session_id(self):
        """Test we can handle a invalid session id"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = '1'
        length = 1

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length))

        assert str(e.value) == 'Session Id should be of type int'


    def test_create_instance_invalid_length(self):
        """Test we can handle a invalid length"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = '1'

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length))

        assert str(e.value) == 'Length should be of type int'


    def test_create_instance_invalid_sequence_no(self):
        """Test we can handle a invalid sequence_no"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        sequence_no = '1'
        flag = 0

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length,
                                sequence_no, flag))

        assert str(e.value) == 'Sequence No should be of type int'


    def test_create_instance_invalid_sequence_no(self):
        """Test we can handle a invalid sequence_no"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1
        sequence_no = 1
        flag = '1'

        with pytest.raises(TypeError) as e:
            Header(HeaderFields(version, packet_type, session_id, length,
                                sequence_no, flag))

        assert str(e.value) == 'Flags should be of type int'


    def test_decode_header(self):
        """Test we can decode a valid TACACS+ header"""

        encoded_header = b'\x01\x01\x01\x00\x00\x00\x00\x01\x00\x00\x00\x01'
        fields = Header.decode(encoded_header)

        assert fields.version == 1
        assert fields.packet_type == 1
        assert fields.session_id == 1
        assert fields.length == 1
        assert fields.sequence_no == 1
        assert fields.flags == 0


    def test_decode_header_with_invalid_bytes(self):
        """Test we can handle a invalid no. of bytes TACACS+ header"""

        encoded_header = b'\x01\x01'

        with pytest.raises(ValueError) as e:
            Header.decode(encoded_header)

        assert str(e.value) == 'Unable to extract header. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_decode_header_with_invalid_encoding(self):
        """Test we can handle a invalid encoding of TACACS+ header"""

        encoded_header = 'This is not a TACACS+ header'

        with pytest.raises(ValueError) as e:
            Header.decode(encoded_header)

        assert str(e.value) == 'Unable to extract header. Not encoded as a' \
                               ' byte-like object'


    def test_get_packet_type_authen(self):
        """Test we can find the authentication packet type from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 0x01
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.packet_type == 'TAC_PLUS_AUTHEN'


    def test_get_packet_type_author(self):
        """Test we can find the authorisation packet type from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 0x01
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.packet_type == 'TAC_PLUS_AUTHOR'


    def test_get_packet_type_acct(self):
        """Test we can find the accounting packet type from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.packet_type == 'TAC_PLUS_ACCT'


    def test_get_default_sequence_no(self):
        """Test we can find the default sequence no from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.sequence_no == 1


    def test_get_sequence_no(self):
        """Test we can find the a sequence no from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length),
                        sequence_no=123)
        assert header.sequence_no == 123


    def test_get_session_id(self):
        """Test we can find the a session id from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.session_id == 123


    def test_get_version(self):
        """Test we can find the a protocol version from a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        assert header.version == 1


    def test_set_body_length(self):
        """Test we can set the body length in a TACACSPlusHeader instance"""

        version = 0x01
        packet_type = flags.TAC_PLUS_ACCT
        session_id = 123
        length = 1

        header = Header(HeaderFields(version, packet_type, session_id, length))
        header.length = 20

        assert header.length == 20
