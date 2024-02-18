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


    def test_invalid_arg_count(self):
        """Test we handle passing a invalid argument count field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorRequestFields(arg_cnt='invalid',
                                         arg_service='shell')

        assert str(e.value) == 'Argument Count should be of type int'
