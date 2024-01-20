"""
Module provides unit tests for the Authentication Start class

Classes:
    TestAuthenStart

Functions:
    None
"""

import six
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import AuthenStartFields
from freetacacs.authentication import TACACSPlusAuthenStart as AuthenStartPacket

class TestAuthenStart:
    """Test class for testing the Authentication Start class"""

    def test_create_instance(self):
        """Test we can create a instance of TACACSPlusAuthenStart class"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 0

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, raw.read(), 'test')

        fields = pkt.decode

        assert isinstance(pkt, AuthenStartPacket)
        assert fields.action == 'TAC_PLUS_AUTHEN_LOGIN'
        assert fields.priv_lvl == 'TAC_PLUS_PRIV_LVL_MIN'
        assert fields.authen_type == 'TAC_PLUS_AUTHEN_TYPE_PAP'
        assert fields.service == 'TAC_PLUS_AUTHEN_SVC_LOGIN'
        assert fields.user == 'test'
        assert fields.port == 'python_tty0'
        assert fields.remote_address == 'python_device'
        assert fields.data == 'test'
        assert pkt.length == 40


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 1
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, raw.read(), 'test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenSTART packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_mismatch(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, raw.read(), 'incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenSTART packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        version = 193
        packet_type = flags.TAC_PLUS_AUTHEN
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthenStartPacket(header, raw.read())

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthenSTART packet. TACACS+' \
                               ' client/server shared key probably does not match'
