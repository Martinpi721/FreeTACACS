import six
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import TACACSPlusAuthenReply as AuthenReply

class TestAuthenReply:
    def test_create_instance_without_body_nor_fields(self):
        """Test we handle failure to pass either body for fields"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        with pytest.raises(TypeError) as e:
            AuthenReply(header, fields=dict(), secret='test')

        assert str(e.value) == '__init__() requires either a byte encoded body' \
                               ' or dictionary of fields'


    def test_create_instance_with_body(self):
        """Test we can create an instance from TACACSPlusAuthenReply class"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        # Convert packet to a byte-stream and create Authentication reply instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenReply(header, raw.read(), 'test')

        assert isinstance(pkt, AuthenReply)


    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        fields = {
                   'status': 'invalid',
                   'flags': 0,
                   'server_msg': 'test',
                   'data': 'test',
                }

        with pytest.raises(ValueError) as e:
            AuthenReply(header, fields=fields, secret='test')

        assert str(e.value) == 'Unable to encode AuthenReply packet. Required' \
                               ' arguments status and flags must be integers'


    def test_invalid_flags(self):
        """Test we handle passing a invalid flags field type"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        fields = {
                   'status': 0,
                   'flags': 'invalid',
                   'server_msg': 'test',
                   'data': 'test',
                }

        with pytest.raises(ValueError) as e:
            AuthenReply(header, fields=fields, secret='test')

        assert str(e.value) == 'Unable to encode AuthenReply packet. Required' \
                               ' arguments status and flags must be integers'


    def test_invalid_server_msg(self):
        """Test we handle passing a invalid server_msg field type"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        fields = {
                   'status': 0,
                   'flags': 0,
                   'server_msg': 0,
                   'data': 'test',
                }

        with pytest.raises(ValueError) as e:
            AuthenReply(header, fields=fields, secret='test')

        assert str(e.value) == 'Unable to encode AuthenReply packet. Required' \
                               ' arguments server_msg and data must be strings'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        fields = {
                   'status': 0,
                   'flags': 0,
                   'server_msg': 'test',
                   'data': 0,
                }

        with pytest.raises(ValueError) as e:
            AuthenReply(header, fields=fields, secret='test')

        assert str(e.value) == 'Unable to encode AuthenReply packet. Required' \
                               ' arguments server_msg and data must be strings'


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthenReply class"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        fields = {
                   'status': 0,
                   'flags': 0,
                   'server_msg': 'test',
                   'data': 'test',
                }

        pkt = AuthenReply(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthenReply)

