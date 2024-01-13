import pytest

import six
import struct

# Import code to be tested
from freetacacs import flags
from freetacacs.packet import TACACSPlusPacket as Packet
from freetacacs.header import TACACSPlusHeader as Header

# Import exceptions

class TestTACACSPlusPacket:
    def test_create_instance(self):
        """Test we can create a instance of TACACSPlusPacket class"""

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 1932205026, 'length': 40})

        raw = six.BytesIO(b'TACACS+ data body')
        pkt = Packet(header, raw.read(), 'test')

        assert isinstance(pkt, Packet)


    def test_deobfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_body = b'\x02\xe5\xad}\x989\xa7\x97\xba\x93\xbbWV\xa1\xad\xa4\xab,\xf9\x9a.g5Z5\xb1\xb2\xb5\xa7q\x92\xf2\n\x13\xd3\xf0\xe3\x9e\xc9\x19'

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 1932205026, 'length': 40})

        raw = six.BytesIO(raw_body)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.deobfuscate == b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_de\xef"\x8a\xbd\xbe\xa5\x85\x0e'


    def test_obfuscation_of_packet_body(self):
        """Test we can unobfuscate packet bodies"""

        raw_body = b'\x01\x00\x02\x01\x04\x0b\r\x04testpython_tty0python_de\xef"\x8a\xbd\xbe\xa5\x85\x0e'

        # Configure the header
        header = Header({'version': 193, 'packet_type': flags.TAC_PLUS_AUTHEN,
                         'session_id': 1932205026, 'length': 40})

        raw = six.BytesIO(raw_body)
        pkt = Packet(header, raw.read(), 'test')

        assert pkt.obfuscate == b'\x02\xe5\xad}\x989\xa7\x97\xba\x93\xbbWV\xa1\xad\xa4\xab,\xf9\x9a.g5Z5\xb1\xb2\xb5\xa7q\x92\xf2\n\x13\xd3\xf0\xe3\x9e\xc9\x19'
