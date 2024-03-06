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


    def test_invalid_arg_count(self):
        """Test we handle passing a invalid argument count field type"""

        with pytest.raises(TypeError) as e:
            fields = AcctRequestFields(arg_cnt='invalid',
                                         args=['service=system'])

        assert str(e.value) == 'Argument Count should be of type int'


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


