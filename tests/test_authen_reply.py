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
