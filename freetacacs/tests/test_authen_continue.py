"""
Module provides unit tests for the Authentication Continue class

Classes:
    TestAuthenContinueFields
    TestAuthenContinue

Functions:
    None
"""

import six
import pytest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header
from freetacacs.authentication import AuthenContinueFields
#from freetacacs.authentication import TACACSPlusAuthenContinue as AuthenContPacket


class TestAuthenContinueFields:
    """Test class for testing the Authentication Continue Fields class"""

    def test_invalid_flags(self):
        """Test we handle passing a invalid flags field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags='invalid',
                                          user_msg='test', data='test')

        assert str(e.value) == 'Flags should be of type int'


    def test_invalid_user_msg(self):
        """Test we handle passing a invalid user_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags=0x00,
                                          user_msg=0, data='test')

        assert str(e.value) == 'User Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthenContinueFields(flags=0x00,
                                          user_msg='test', data=0)

        assert str(e.value) == 'Data should be of type string'


    def test_default_authentication_continue_fields_string(self):
        """Test we can get the default string representation of authentication continue fields"""

        fields = AuthenContinueFields()

        assert str(fields) == 'flags: TAC_PLUS_CONTINUE_FLAG_ABORT, user_msg: , data: '


