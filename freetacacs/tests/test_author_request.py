"""
Module provides unit tests for the Authorisation Request class

Classes:
    TestAuthorRequestFields

Functions:
    None
"""

import six
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authorisation import AuthorRequestFields


class TestAuthorRequestFields:
    """Test class for testing the Authorisation request Fields class"""


    def test_invalid_arg_service(self):
        """Test we handle passing a invalid argument service field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_service=None)

        assert str(e.value) == 'Argument Service should be of type string'


    def test_invalid_arg_count(self):
        """Test we handle passing a invalid argument count field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_cnt='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument Count should be of type int'


    def test_invalid_arg_protocol(self):
        """Test we handle passing a invalid argument protocol field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_protocol=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument Protocol should be of type string'


    def test_invalid_arg_cmd(self):
        """Test we handle passing a invalid argument CMD field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_cmd=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument CMD should be of type string'


    def test_invalid_arg_cmd_arg(self):
        """Test we handle passing a invalid argument CMD-ARG field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_cmd_arg=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument CMD-ARG should be of type string'


    def test_invalid_arg_acl(self):
        """Test we handle passing a invalid argument ACL field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_acl='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument ACL should be of type int'


    def test_invalid_arg_inacl(self):
        """Test we handle passing a invalid argument in ACL field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_inacl=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument in ACL should be of type string'


    def test_invalid_arg_outacl(self):
        """Test we handle passing a invalid argument out ACL field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_outacl=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument out ACL should be of type string'


    def test_invalid_arg_addr(self):
        """Test we handle passing a invalid argument ip address field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_addr=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument IP Address should be of type string'


    def test_invalid_arg_addr_pool(self):
        """Test we handle passing a invalid argument ip pool field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_addr_pool=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument IP Pool should be of type string'


    def test_invalid_arg_timeout(self):
        """Test we handle passing a invalid argument timeout field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_timeout='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument Timeout should be of type int'


    def test_invalid_arg_idletimeout(self):
        """Test we handle passing a invalid argument Idle Timeout field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_idletimeout='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument Idle Timeout should be of type int'


    def test_invalid_arg_autocmd(self):
        """Test we handle passing a invalid argument Auto CMD field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_autocmd=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument Auto CMD should be of type string'


    def test_invalid_arg_noescape(self):
        """Test we handle passing a invalid argument noescape field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_noescape=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument noescape should be of type boolean'


    def test_invalid_arg_nohangup(self):
        """Test we handle passing a invalid argument nohangup field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_nohangup=None,
                                         arg_service='shell')

        assert str(e.value) == 'Argument nohangup should be of type boolean'


    def test_invalid_arg_priv_lvl(self):
        """Test we handle passing a invalid argument priv level field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_priv_lvl='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument Priviledge Level should be of type int'


    def test_invalid_authen_method(self):
        """Test we handle passing a invalid authentication method field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_method='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Authentication Method should be of type int'


    def test_invalid_priv_lvl(self):
        """Test we handle passing a invalid priviledge level field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(priv_lvl='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Priviledge Level should be of type int'


    def test_invalid_authen_type(self):
        """Test we handle passing a invalid authentication type field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_type='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Authentication Type should be of type int'


    def test_invalid_authen_service(self):
        """Test we handle passing a invalid authentication service type field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(authen_service='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Authentication Service should be of type int'


    def test_invalid_user(self):
        """Test we handle passing a invalid user field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(user=123, arg_service='shell')

        assert str(e.value) == 'User should be of type string'


    def test_invalid_port(self):
        """Test we handle passing a invalid port field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(port=123, arg_service='shell')

        assert str(e.value) == 'Port should be of type string'


    def test_invalid_remote_address(self):
        """Test we handle passing a invalid remote address field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(remote_address=123,
                                         arg_service='shell')

        assert str(e.value) == 'Remote Address should be of type string'
