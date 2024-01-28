"""
Module provides pytest configuration

Classes:
    TestAuthenReply

Functions:
    None
"""

import os
import pytest

@pytest.fixture
def setup_fixture():
    # Setup logic before running each test

    # Optionally, return any setup data that needs to be passed to the tests
    data_dir = '/'.join([os.path.dirname(os.path.realpath(__file__)), 'data'])
    yield { 'data_dir' : data_dir}

    # Teardown logic after the test
    # Additional teardown code goes here



