"""
Module provides unit tests for the Authorisation Request class

Classes:
    TestAuthorRequestFields

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
