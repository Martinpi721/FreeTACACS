"""
Module provides unit tests for the Accounting Reply class

Classes:
    TestAcctReplyFields
    TestAcctReply

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
from freetacacs.accounting import AcctReplyFields


class TestAcctReplyFields(unittest.TestCase):
    """Test class for testing the Accounting reply Fields class"""

    def test_invalid_status(self):
        """Test we handle passing a invalid status field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status='invalid')

        assert str(e.value) == 'Status should be of type int'


    def test_invalid_server_message(self):
        """Test we handle passing a invalid server_msg field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       server_msg=1)

        assert str(e.value) == 'Server Message should be of type string'


    def test_invalid_data(self):
        """Test we handle passing a invalid data field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                       data=1)

        assert str(e.value) == 'Data should be of type string'


    def test_default_accounting_reply_fields_string(self):
        """Test we can get the default string representation of accounting reply fields"""

        fields = AcctReplyFields()

        assert str(fields) == 'status: TAC_PLUS_ACCT_STATUS_SUCCESS, server_msg: , data: '


    def test_default_accounting_reply_fields_dict(self):
        """Test we can get the default dict representation of accounting reply fields"""

        fields = AcctReplyFields()

        assert vars(fields) == {
                                 'status'     : 1,
                                 'server_msg' : '',
                                 'data'       : '',
                                }
