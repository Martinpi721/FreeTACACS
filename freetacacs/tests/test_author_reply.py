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
from twisted.logger import LogLevel, capturedLogs

# Import code to be tested
from freetacacs import flags
from freetacacs.header import HeaderFields
from freetacacs.header import TACACSPlusHeader as Header

from freetacacs.authorisation import (AuthorReplyFields,
                                      MissingServiceArgument,
                                      MissingCmdArgument)
from freetacacs.authorisation import TACACSPlusAuthorReply as AuthorReplyPacket


class TestAuthorReplyFields(unittest.TestCase):
    """Test class for testing the Authorisation request Fields class"""


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


    def test_default_author_reply_fields_dict(self):
        """Test we can get the default dict representation of author reply fields"""

        fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

        assert vars(fields) == {
                                 'status'     : 1,
                                 'arg_cnt'    : 1,
                                 'server_msg' : '',
                                 'data'       : '',
                                 'args'       : []
                                }


    def test_set_author_reply_fields(self):
        """Test we can set the author request fields"""

        args=['service=shell', 'cmd=ls -l']
        fields = AuthorReplyFields(status=flags.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                                   arg_cnt=len(args),
                                   server_msg='Message from server',
                                   data='Data from server',
                                   args=args)

        assert str(fields) == 'status: TAC_PLUS_AUTHOR_STATUS_PASS_ADD,' \
                              ' arg_cnt: 2, server_msg: Message from server,' \
                              ' data: Data from server, arg_1: service=shell,' \
                              ' arg_2: cmd=ls -l'


    def test_invalid_argument_startswith_equal(self):
        """Test we can ignore a invalid argument that starts with ="""

        args=[
               'service=system',
               '=service',
               '==',
               '=',
             ]

        with capturedLogs() as events:
            fields = AuthorReplyFields(arg_cnt=len(args), args=args)

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
            fields = AuthorReplyFields(arg_cnt=len(args), args=args)

        assert events[0]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[1]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'
        assert events[2]['text'] == 'Ignoring invalid authorisation argument' \
                                   ' should not start with either [=*]'


    def test_invalid_missing_service_argument(self):
        """Test we can handle the missing service argument"""

        args=[
               'protocol=ppp',
             ]

        with pytest.raises(MissingServiceArgument) as e:
            fields = AuthorReplyFields(arg_cnt=len(args), args=args)


    def test_invalid_missing_cmd_argument(self):
        """Test we can handle the missing cmd argument"""

        args=[
               'service=shell',
             ]

        with pytest.raises(MissingCmdArgument) as e:
            fields = AuthorReplyFields(arg_cnt=len(args), args=args)


class TestAuthorReply(unittest.TestCase):
    """Test class for testing the Authorisation Request class"""

    def test_create_instance_with_body(self):
        """Test we can create a instance of TACACSPlusAuthorReply class"""
        pass


    def test_create_instance_with_fields(self):
        """Test we can create an instance from TACACSPlusAuthorReply class"""

        version = 192
        packet_type = flags.TAC_PLUS_AUTHOR
        session_id = 2620865572
        length = 40

        # Configure the header
        header = Header(HeaderFields(version, packet_type, session_id, length))

        args = ['service=system']
        fields = AuthorReplyFields(status=0x00, arg_cnt=len(args),
                                   server_msg='test', data='test', args=args)
        pkt = AuthorReplyPacket(header, fields=fields, secret='test')

        assert isinstance(pkt, AuthorReplyPacket)
        assert str(pkt) == 'status: 0, arg_cnt: 1, server_msg_len: 4,' \
                ' data_len: 4, arg_1_len: 14, server_msg: test, data: test,' \
                ' arg_1: service=system'
        assert bytes(pkt) == b'\xc0\x02\x01\x00\x9c7<$\x00\x00\x00\x1d\x83\xac\xf7\xcb\xc9!\xe7\xe5\xcc/\xa2=9v\xc1Z\xb6\xd3\xfb\x8d\x8c\xf6\x95\xdfWL\x80\xe5\xc0'
