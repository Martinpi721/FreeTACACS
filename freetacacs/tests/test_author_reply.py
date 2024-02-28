"""
Module provides unit tests for the Authorisation Reply class

Classes:
    TestAuthorReplyFields
    TestAuthorReply

Functions:
    None
"""

import six
import pytest
from twisted.trial import unittest

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header

from freetacacs.authorisation import AuthorReplyFields
from freetacacs.authorisation import TACACSPlusAuthorReply as AuthorReplyPacket


class TestAuthorReplyFields(unittest.TestCase):
    """Test class for testing the Authorisation request Fields class"""


    def test_missing_status(self):
        """Test we handle passing a missing field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields()

        assert str(e.value) == "__init__() missing 1 required positional argument: 'status'"


    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields(status='invalid')

        assert str(e.value) == 'Status should be of type int'


    def test_invalid_arg_cnt(self):
        """Test we handle passing a invalid arg_cnt field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       arg_cnt='invalid')

        assert str(e.value) == 'Argument Count should be of type int'


    def test_invalid_server_message(self):
        """Test we handle passing a invalid server_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       server_msg=1)

        assert str(e.value) == 'Server Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       data=1)

        assert str(e.value) == 'Data should be of type string'


    def test_invalid_args(self):
        """Test we handle passing a invalid args field type"""

        with pytest.raises(TypeError) as e:
            fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       args=1)

        assert str(e.value) == 'Arguments should be of type list'


    def test_default_author_reply_fields_string(self):
        """Test we can get the default string representation of author reqeply fields"""

        fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

        assert str(fields) == 'status: TAC_PLUS_AUTHOR_STATUS_PASS_ADD,' \
                              ' arg_cnt: 1, server_msg: ,' \
                              ' data: '


class TestAuthorReply(unittest.TestCase):
    """Test class for testing the Authorisation Request class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAuthorReply class"""
        pass

