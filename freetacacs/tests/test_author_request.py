"""
Module provides unit tests for the Authorisation Request class

Classes:
    TestAuthorRequestFields
    TestAuthorRequest

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
from freetacacs.authorisation import (AuthorRequestFields,
                                      MissingServiceArgument,
                                      MissingCmdArgument)
from freetacacs.authorisation import TACACSPlusAuthorRequest as AuthorRequestPacket


class TestAuthorRequestFields(unittest.TestCase):
    """Test class for testing the Authorisation request Fields class"""


    def test_invalid_arg_count(self):
        """Test we handle passing a invalid argument count field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_cnt='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Argument Count should be of type int'


    def test_invalid_authen_method(self):
        """Test we handle passing a invalid authentication method field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_method='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Authentication Method should be of type int'


    def test_invalid_priv_lvl(self):
        """Test we handle passing a invalid priviledge level field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(priv_lvl='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Priviledge Level should be of type int'


    def test_invalid_authen_type(self):
        """Test we handle passing a invalid authentication type field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_type='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Authentication Type should be of type int'


    def test_invalid_authen_service(self):
        """Test we handle passing a invalid authentication service type field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_service='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Authentication Service should be of type int'


    def test_invalid_user(self):
        """Test we handle passing a invalid user field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(user=123, args=['service=system'])

        assert str(e.value) == 'User should be of type string'


    def test_invalid_port(self):
        """Test we handle passing a invalid port field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(port=123, args=['service=system'])

        assert str(e.value) == 'Port should be of type string'


    def test_invalid_remote_address(self):
        """Test we handle passing a invalid remote address field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(remote_address=123,
                                         args=['service=system'])

        assert str(e.value) == 'Remote Address should be of type string'


    def test_default_author_request_fields_string(self):
        """Test we can get the default string representation of author request fields"""

        args=['service=system']
        fields = AuthorRequestFields(arg_cnt=len(args), args=args)

        assert str(fields) == 'priv_lvl: TAC_PLUS_PRIV_LVL_MIN, authen_method:' \
                              ' TAC_PLUS_AUTHEN_METH_NOT_SET, authen_service:' \
                              ' TAC_PLUS_AUTHEN_SVC_NONE, user: , port: ,' \
                              ' arg_cnt: 1, remote_address: , arg_service=system'


    def test_default_author_request_fields_dict(self):
        """Test we can get the default dict representation of author request fields"""

        args=['service=system']
        fields = AuthorRequestFields(arg_cnt=len(args), args=args)

        assert vars(fields) == {
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


    def test_set_author_request_fields(self):
        """Test we can set the author request fields"""

        args=['service=system']
        fields = AuthorRequestFields(arg_cnt=len(args),
                                     authen_method=flags.TAC_PLUS_AUTHEN_METH_ENABLE,
                                     priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                     authen_type=flags.TAC_PLUS_AUTHEN_LOGIN,
                                     authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                     user='jsmith',
                                     port='python_tty0',
                                     remote_address='python_device',
                                     args=args)

        assert str(fields) == 'priv_lvl: TAC_PLUS_PRIV_LVL_MIN,' \
                              ' authen_method: TAC_PLUS_AUTHEN_METH_ENABLE,' \
                              ' authen_service: TAC_PLUS_AUTHEN_SVC_LOGIN,' \
                              ' user: jsmith, port: python_tty0, arg_cnt: 1,' \
                              ' remote_address: python_device, arg_service=system'


    def test_invalid_argument_startswith_equal(self):
        """Test we can ignore a invalid argument that starts with ="""

        args=[
               'service=system',
               '=service',
               '==',
               '=',
             ]

        with capturedLogs() as events:
            fields = AuthorRequestFields(arg_cnt=len(args), args=args)

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
            fields = AuthorRequestFields(arg_cnt=len(args), args=args)

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
            fields = AuthorRequestFields(arg_cnt=len(args), args=args)


    def test_invalid_missing_cmd_argument(self):
        """Test we can ignore a invalid argument that contains no seperator"""

        args=[
               'service=shell',
             ]

        with pytest.raises(MissingCmdArgument) as e:
            fields = AuthorRequestFields(arg_cnt=len(args), args=args)


class TestAuthorRequest(unittest.TestCase):
    """Test class for testing the Authorisation Request class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAuthorRequest class"""

        raw_pkt = b'\xc0\x02\x01\x004\x04\x12\xe7\x00\x00\x005\xabh\x1e\xb8(\x811\xae8\xb2\xc4\xa8a\x97pj\xc7\x9dj~\xa7\xe3\xba\xca+^\x13DP2\x1b\x8e\x80\x0f\xf5\x8f\x05j\xb6\xd6\x93\xb7 Nd\xb4\x05\xc9\xaa\xd8\xc3\xab\x9b'

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 872682215
        length = 53

        # What should be returned when we call __str__ on object
        required_str = 'authen_method: 6, priv_lvl: 0, authen_type: 1,' \
                ' authen_service: 1, user_len: 6, port_len: 11,' \
                ' rem_addr_len: 13, arg_cnt: 1, arg_1_len: 14, user: myuser,' \
                ' port: python_tty0, rem_addr: python_device,' \
                ' arg_1: service=system'

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthorRequestPacket(header, body=raw.read(), secret='test')

        fields = pkt.decode

        assert isinstance(pkt, AuthorRequestPacket)
        assert fields.authen_method == 6
        assert fields.priv_lvl == 0
        assert fields.authen_type == 1
        assert fields.authen_service == 1
        assert fields.user == 'myuser'
        assert fields.port == 'python_tty0'
        assert fields.remote_address == 'python_device'
        assert fields.args == ['service=system']
        assert pkt.length == 53
        assert str(pkt) == required_str


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthorRequest class"""

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 2620865572
        length = 53

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        fields = AuthorRequestFields(authen_method=flags.TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                                     priv_lvl=flags.TAC_PLUS_PRIV_LVL_MIN,
                                     authen_type=flags.TAC_PLUS_AUTHEN_TYPE_NOT_SET,
                                     authen_service=flags.TAC_PLUS_AUTHEN_SVC_LOGIN,
                                     user='jsmith',
                                     port='python_tty0',
                                     remote_address='python_device',
                                     args=['service=system'])

        pkt = AuthorRequestPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthorRequestPacket)
        assert str(pkt) == 'authen_method: 6, priv_lvl: 0, authen_type: 0, authen_service: 1,' \
                           ' user_len: 6, port_len: 11, rem_addr_len: 13,' \
                           ' arg_cnt: 1, arg_1_len: 14, user: jsmith, port: python_tty0,' \
                           ' rem_addr: python_device, arg_1: service=system'


    def test_incorrect_session_id(self):
        """Test we can handle a invalid session id"""

        raw_pkt = b'\xc0\x02\x01\x004\x04\x12\xe7\x00\x00\x005\xabh\x1e\xb8(\x811\xae8\xb2\xc4\xa8a\x97pj\xc7\x9dj~\xa7\xe3\xba\xca+^\x13DP2\x1b\x8e\x80\x0f\xf5\x8f\x05j\xb6\xd6\x93\xb7 Nd\xb4\x05\xc9\xaa\xd8\xc3\xab\x9b'

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 1
        length = 53

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthorRequestPacket(header, body=raw.read(), secret='test')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthorRequest packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_mismatch(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b'\xc0\x02\x01\x004\x04\x12\xe7\x00\x00\x005\xabh\x1e\xb8(\x811\xae8\xb2\xc4\xa8a\x97pj\xc7\x9dj~\xa7\xe3\xba\xca+^\x13DP2\x1b\x8e\x80\x0f\xf5\x8f\x05j\xb6\xd6\x93\xb7 Nd\xb4\x05\xc9\xaa\xd8\xc3\xab\x9b'

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 872682215
        length = 53

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthorRequestPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthorRequest packet. TACACS+' \
                               ' client/server shared key probably does not match'


    def test_shared_key_missing(self):
        """Test we can handle client/server shared key mismatch"""

        raw_pkt = b'\xc0\x02\x01\x004\x04\x12\xe7\x00\x00\x005\xabh\x1e\xb8(\x811\xae8\xb2\xc4\xa8a\x97pj\xc7\x9dj~\xa7\xe3\xba\xca+^\x13DP2\x1b\x8e\x80\x0f\xf5\x8f\x05j\xb6\xd6\x93\xb7 Nd\xb4\x05\xc9\xaa\xd8\xc3\xab\x9b'

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 872682215
        length = 53

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        # Convert packet to a byte-stream and create Authorisation request instance
        raw = six.BytesIO(raw_pkt)
        raw.seek(12)
        pkt = AuthorRequestPacket(header, body=raw.read(), secret='incorrect')

        with pytest.raises(ValueError) as e:
            pkt.decode

        assert str(e.value) == 'Unable to decode AuthorRequest packet. TACACS+' \
                               ' client/server shared key probably does not match'
