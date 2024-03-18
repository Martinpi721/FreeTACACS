"""
Module provides unit tests for the Accounting Request class

Classes:
    TestAcctRequestFields
    TestAcctRequest

Functions:
    None
"""

import six
import pytest
from twisted.trial import unittest
from twisted.logger import LogLevel, capturedLogs

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.packet import MissingServiceArgument, MissingCmdArgument
from freetacacs.accounting import AcctRequestFields
from freetacacs.accounting import TACACSPlusAccountRequest as AcctRequestPacket


class TestAcctRequestFields(unittest.TestCase):
    """Test class for testing the Accounting request Fields class"""

    def test_invalid_flags_field(self):
        """Test we handle passing a invalid flags field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(flags='invalid')

        assert str(e.value) == 'Flags should be of type int'


    def test_invalid_authen_method_field(self):
        """Test we handle passing a invalid authen method field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(authen_method='invalid')

        assert str(e.value) == 'Authentication method should be of type int'


    def test_invalid_priv_lvl(self):
        """Test we handle passing a invalid privilege level field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(priv_lvl='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Privilege Level should be of type int'


    def test_invalid_authen_type(self):
        """Test we handle passing a invalid authentication type field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(authen_type='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Authentication Type should be of type int'


    def test_invalid_authen_service(self):
        """Test we handle passing a invalid authentication service type field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(authen_service='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Authentication Service should be of type int'


    def test_invalid_user(self):
        """Test we handle passing a invalid user field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(user=123, args=['service=system'])

        assert str(e.value) == 'User should be of type string'


    def test_invalid_port(self):
        """Test we handle passing a invalid port field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(port=123, args=['service=system'])

        assert str(e.value) == 'Port should be of type string'


    def test_invalid_remote_address(self):
        """Test we handle passing a invalid remote address field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(remote_address=123,
                                         args=['service=system'])

        assert str(e.value) == 'Remote Address should be of type string'


    def test_invalid_arg_count(self):
        """Test we handle passing a invalid argument count field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(arg_cnt='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Argument Count should be of type int'


    def test_default_accounting_request_fields_string(self):
        """Test we can get the default string representation of accounting request fields"""

        args=['service=system']
        fields = AcctRequestFields(arg_cnt=len(args), args=args)

        assert str(fields) == 'flags: TAC_PLUS_ACCT_FLAG_START,' \
                              ' authen_method: TAC_PLUS_AUTHEN_METH_NOT_SET,' \
                              ' priv_lvl: TAC_PLUS_PRIV_LVL_MIN,' \
                              ' authen_type: TAC_PLUS_AUTHEN_TYPE_NOT_SET,' \
                              ' authen_service: TAC_PLUS_AUTHEN_SVC_NONE,' \
                              ' user: , port: , arg_cnt: 1, remote_address: ,' \
                              ' arg_1: service=system'


    def test_default_accounting_request_fields_dict(self):
        """Test we can get the default dict representation of accounting request fields"""

        args=['service=system']
        fields = AcctRequestFields(arg_cnt=len(args), args=args)

        assert vars(fields) == {
                                 'flags'           : 2,
                                 'arg_cnt'         : 1,
                                 'authen_method'   : 0,
                                 'priv_lvl'        : 0,
                                 'authen_type'     : 0,
                                 'authen_service'  : 0,
                                 'user'            : '',
                                 'port'            : '',
                                 'remote_address'  : '',
                                 'args'            : args
                                }


    def test_invalid_argument_startswith_equal(self):
        """Test we can ignore a invalid argument that starts with ="""

        args=[
               'service=system',
               '=service',
               '==',
               '=',
             ]

        with capturedLogs() as events:
            fields = AcctRequestFields(arg_cnt=len(args), args=args)

        assert events[0]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[1]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[2]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'


    def test_invalid_argument_startswith_astrisk(self):
        """Test we can ignore a invalid argument that starts with *"""

        args=[
               'service=system',
               '*service',
               '**',
               '*',
             ]

        with capturedLogs() as events:
            fields = AcctRequestFields(arg_cnt=len(args), args=args)

        assert events[0]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[1]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[2]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'


    def test_invalid_missing_service_argument(self):
        """Test we can ignore a invalid argument that contains no seperator"""

        args=[
               'protocol=ppp',
             ]

        with pytest.raises(MissingServiceArgument) as e:
            fields = AcctRequestFields(arg_cnt=len(args), args=args)


    def test_invalid_missing_cmd_argument(self):
        """Test we can ignore a invalid argument that contains no seperator"""

        args=[
               'service=shell',
             ]

        with pytest.raises(MissingCmdArgument) as e:
            fields = AcctRequestFields(arg_cnt=len(args), args=args)


class TestAccountRequest(unittest.TestCase):
    """Test class for testing the Aaccounting Request class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAccontRequest class"""

        raw_pkt = b'\xc0\x03\x01\x00\xc3\xb0\xd0\xfc\x00\x00\x00~\x1b\xb4\xfa\x8e7ns\xf3\\\x9fF\xe1\xdf\xbcZHd\xb5A\r\x90Zd9\x07\xd5\xb4\xffI\x8c2<\x01\xa4\xec\t\x95pl\x15\x9d\xc6\xbd\x03\xd66\xdc\xe7c\x07f\xda\xa9\xe6\x83\xaf\xacX\xf6\xa3\xfd\x9egWn\xb5x@\x98Q~\x7f9\n\xf0\x00\xa8K\xa9\x88\xd5:\xa7#K\xf1=\x18\xe2\xe3Tqp:\xaf\x00@\x03\xf3\xcdoU\x92\x12\x00\t\x1f\x81t@G\x91AF\xbe\xb6\xc5\x8ft}\xec\x02\x99W\xdaK'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 3283144956

        # What should be returned when we call __str__ on object
        required_str = 'flags: 2, authen_method: 6, priv_lvl: 0, authen_type: 1,' \
                ' authen_service: 1, user_len: 6, port_len: 11,' \
                ' rem_addr_len: 13, arg_cnt: 5, arg_1_len: 12,' \
                ' arg_2_len: 21, arg_3_len: 20, arg_4_len: 15,' \
                ' arg_5_len: 14, user: myuser,' \
                ' port: python_tty0, rem_addr: python_device,' \
                ' arg_1: task_id=1234, arg_2: start_time=1709850048,' \
                ' arg_3: stop_time=1709850058, arg_4: elapsed_time=10,' \
                ' arg_5: service=system'

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctRequestPacket(header, body=raw.read(), secret='test')

        fields = pkt.decode

        assert isinstance(pkt, AcctRequestPacket)
        assert fields.authen_method == 6
        assert fields.priv_lvl == 0
        assert fields.authen_type == 1
        assert fields.authen_service == 1
        assert fields.user == 'myuser'
        assert fields.port == 'python_tty0'
        assert fields.remote_address == 'python_device'
        assert fields.args == ['task_id=1234',
                               'start_time=1709850048',
                               'stop_time=1709850058',
                               'elapsed_time=10',
                               'service=system']
        assert pkt.length == 126
        assert str(pkt) == required_str


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAcctRequest class"""

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 2620865572

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        fields = AcctRequestFields(flags=flags.TAC_PLUS_ACCT_FLAG_START,
                                   authen_method=flags.TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                   priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                   authen_type=flags.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
                                   authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                   user='jsmith',
                                   port='python_tty0',
                                   remote_address='python_device',
                                   args=['task_id=1234',
                                         'start_time=1709850048',
                                         'stop_time=1709850058',
                                         'elapsed_time=10',
                                         'service=system'])

        pkt = AcctRequestPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AcctRequestPacket)
        assert str(pkt) == 'flags: 2, authen_method: 6, priv_lvl: 0, authen_type: 0,' \
                ' authen_service: 1, user_len: 6, port_len: 11,' \
                ' rem_addr_len: 13, arg_cnt: 5, arg_1_len: 12,' \
                ' arg_2_len: 21, arg_3_len: 20, arg_4_len: 15,' \
                ' arg_5_len: 14, user: jsmith,' \
                ' port: python_tty0, rem_addr: python_device,' \
                ' arg_1: task_id=1234, arg_2: start_time=1709850048,' \
                ' arg_3: stop_time=1709850058, arg_4: elapsed_time=10,' \
                ' arg_5: service=system'
        assert bytes(pkt) == b'\xc0\x03\x01\x00\x9c7<$\x00\x00\x00~\x81\xab\xf7\xcf\xc8#\xe2\x9c\xacP\xc3]S\x0b\xdfZ\xbe\xc8\xf9\x8c\x9f\xea\xdc\xc4AQ\xab\xf4\xd9\xab\xb7y\xb6\x8c\xda15\xda}\xab_D9v\x08g\xfdtZ\xaf4\x0e\xf3\xda\xf7\xcc\xb2\xe0\x00i\xcf#\xe0\xacu\xed\xd4\xc2\x8c\xeac|\xdd\x16\xe7\x88\xab\xa6\xc3\xc5\xbaC\xf6\xed\x06\x05\x90\\]\xbd\xbfp\xaa\\\xd5\xf1\xba\xe1"#\x82\x82=\x1c\xff\xb0ig\xffUD\x1fp\xf6\x0c\x9d\xdeIf\x91\xfb\x93]\xc6\xde\xde'


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b'\xc0\x03\x01\x00\xc3\xb0\xd0\xfc\x00\x00\x00~\x1b\xb4\xfa\x8e7ns\xf3\\\x9fF\xe1\xdf\xbcZHd\xb5A\r\x90Zd9\x07\xd5\xb4\xffI\x8c2<\x01\xa4\xec\t\x95pl\x15\x9d\xc6\xbd\x03\xd66\xdc\xe7c\x07f\xda\xa9\xe6\x83\xaf\xacX\xf6\xa3\xfd\x9egWn\xb5x@\x98Q~\x7f9\n\xf0\x00\xa8K\xa9\x88\xd5:\xa7#K\xf1=\x18\xe2\xe3Tqp:\xaf\x00@\x03\xf3\xcdoU\x92\x12\x00\t\x1f\x81t@G\x91AF\xbe\xb6\xc5\x8ft}\xec\x02\x99W\xdaK'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 1

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctRequestPacket(header, body=raw.read(), secret='test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AcctRequest packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b'\xc0\x03\x01\x00\xc3\xb0\xd0\xfc\x00\x00\x00~\x1b\xb4\xfa\x8e7ns\xf3\\\x9fF\xe1\xdf\xbcZHd\xb5A\r\x90Zd9\x07\xd5\xb4\xffI\x8c2<\x01\xa4\xec\t\x95pl\x15\x9d\xc6\xbd\x03\xd66\xdc\xe7c\x07f\xda\xa9\xe6\x83\xaf\xacX\xf6\xa3\xfd\x9egWn\xb5x@\x98Q~\x7f9\n\xf0\x00\xa8K\xa9\x88\xd5:\xa7#K\xf1=\x18\xe2\xe3Tqp:\xaf\x00@\x03\xf3\xcdoU\x92\x12\x00\t\x1f\x81t@G\x91AF\xbe\xb6\xc5\x8ft}\xec\x02\x99W\xdaK'

        packet_type = flags.TAC_PLUS_ACCT
        session_id = 3283144956

        # Configure the header
        header = Header(HeaderFields(packet_type=packet_type,
                                     session_id=session_id))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AcctRequestPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AcctRequest packet. TACACS+' \
                               ' client/server shared key probably does not match'
