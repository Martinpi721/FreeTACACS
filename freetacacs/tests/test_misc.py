"""
Module provides unit tests for the misc module

Classes:
    TestCreateLogDict

Functions:
    None
"""

from twisted.trial import unittest

# Import code to be tested
from freetacacs.header import HeaderFields
from freetacacs.authentication import AuthenStartFields
from freetacacs.authentication import AuthenReplyFields
from freetacacs.misc import create_log_dict

class TestCreateLogDict(unittest.TestCase):
    """Class to test the create_log_dict function"""

    def test_create_log_dict_for_auth_start(self):
        """Test we can create a valid log dictionary for auth start"""

        required_dict = {'action': 1, 'authen_type': 1, 'data': 'test',
                        'flags': 0, 'length': 0, 'packet_type': 1,
                        'port': '1234', 'priv_lvl': 1, 'remote_address': 'temp',
                        'sequence_no': 1, 'authen_service': 1, 'session_id': 123,
                        'user': 'test', 'version': 193}

        header = HeaderFields(version=193, packet_type=0x01, session_id=123)
        body = AuthenStartFields(action=0x01, priv_lvl=0x01, authen_service=0x01,
                                 user='test', port='1234', remote_address='temp',
                                 authen_type=0x01, data='test')

        rslt_dict = create_log_dict(header, body)

        self.assertDictEqual(rslt_dict, required_dict)


    def test_create_log_dict_for_auth_reply(self):
        """Test we can create a valid log dictionary for auth reply"""

        required_dict = {'status': 1, 'flags': 1, 'server_msg': 'test',
                         'data': 'temp', 'version': 193, 'packet_type': 0x01,
                         'session_id': 123, 'length': 0, 'sequence_no': 1}

        header = HeaderFields(version=193, packet_type=0x01, session_id=123)
        body = AuthenReplyFields(status=0x01, flags=0x01, server_msg='test',
                                 data='temp')

        rslt_dict = create_log_dict(header, body)

        self.assertDictEqual(rslt_dict, required_dict)
