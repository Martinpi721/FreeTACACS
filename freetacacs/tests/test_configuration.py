"""
Module provides unit tests for the configuration module

Classes:
    TestAuthenReply

Functions:
    None
"""

import pytest

# Import code to be tested
from freetacacs.configuration import load_config

class TestLoadConfig:
    """Test class for testing the load_config function"""

    def test_filepath_doesnt_exist(self):
        """Test we handle passing a filepath that doesn't exist"""

        with pytest.raises(FileNotFoundError) as e:
            load_config('/tmp/missing')

        assert str(e.value) == "[Errno 2] No such file or directory: '/tmp/missing'"

    def test_valid_json_with_valid_keys(self, setup_fixture):
        """Test we handle a yaml file with valid data set"""

        required = {
                     'secrets_type': 'file',
                     'secrets_file': '/etc/freetacacs/shared_secrets.json',
                     'auth_type': 'pam',
                     'author_type': 'file',
                     'author_file': '/etc/freetacacs/authorisations.json',
                    }

        file_path = f"{setup_fixture['data_dir']}/configuration/config.json"
        rslt = load_config(file_path)

        assert rslt == required

    def test_valid_yaml_with_valid_keys(self, setup_fixture):
        """Test we handle a yaml file with valid data set"""

        required = {
                     'secrets_type': 'file',
                     'secrets_file': '/etc/freetacacs/shared_secrets.json',
                     'auth_type': 'pam',
                     'author_type': 'file',
                     'author_file': '/etc/freetacacs/authorisations.json',
                    }

        file_path = f"{setup_fixture['data_dir']}/configuration/config.yaml"
        rslt = load_config(file_path)

        assert rslt == required
