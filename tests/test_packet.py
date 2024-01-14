import pytest

import six
import struct

# Import code to be tested
from freetacacs.flags import TAC_PLUS_AUTHEN
from freetacacs.packet import TACACSPlusPacket as Packet
from freetacacs.header import TACACSPlusHeader as Header

# Import exceptions

class TestTACACSPlusPacket:
    def test_create_instance(self):
        """Test we can create a instance of TACACSPlusPacket class"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': TAC_PLUS_AUTHEN,
                         'session_id': 1932205026, 'length': 40})

        raw = six.BytesIO(b'TACACS+ data body')
        pkt = Packet(header, raw.read(), 'test')

        assert isinstance(pkt, Packet)


    def test_deobfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_pkt = b"\xc1\x01\x01\x00\x9c7<$\x00\x00\x00(\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"

        # Configure the header
        header = Header({'version': 193, 'packet_type': TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.deobfuscate == b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'


    def test_obfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_plain_body = b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_devicetest'

        # Configure the header
        header = Header({'version': 193, 'packet_type': TAC_PLUS_AUTHEN,
                         'session_id': 2620865572, 'length': 40})

        # Convert packet to a byte-stream and create Authentication start instance
        raw = six.BytesIO(raw_plain_body)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.obfuscate == b"\xa3\x0c\xe1\xb1\x97\xf4f\x10M\xbb\xed3z:\xab44f\xed\xed\x7f\xa2\x1d\xdcL'E\xd3\x15\xbc\x8e\x11r\xc6\x9b\\\x16Tqg"
