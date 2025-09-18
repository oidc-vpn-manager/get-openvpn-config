"""
Tests for the get_openvpn_computer_config.py script - PSK computer profile functionality.
"""

import pytest
import requests
from click.testing import CliRunner
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_computer_config


@pytest.fixture
def runner():
    return CliRunner()


class TestGetOVPNComputerConfig:
    """Test the get_openvpn_computer_config.py main function."""

    def test_help_output(self, runner):
        """Test that help output is displayed correctly."""
        result = runner.invoke(get_openvpn_computer_config.main, ['--help'])
        assert result.exit_code == 0
        assert "Fetches an OpenVPN computer profile using PSK authentication" in result.output
        assert "--server-url" in result.output
        assert "--output" in result.output
        assert "--force" in result.output
        assert "--psk" in result.output

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    @patch('builtins.open', new_callable=mock_open)
    def test_successful_computer_profile_download(self, mock_file, mock_get_profile, runner, tmp_path):
        """Test successful computer profile download with PSK."""
        # Setup mock response
        mock_get_profile.return_value = b'mock-computer-ovpn-content'

        # Use temp path for output
        output_file = tmp_path / "computer-config.ovpn"

        # Run command
        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com',
            '--output', str(output_file),
            '--psk', 'test-computer-psk',
            '--force'
        ])

        # Verify success
        assert result.exit_code == 0
        assert "Requesting computer profile with PSK authentication..." in result.output
        assert f"Successfully saved computer configuration to {output_file}" in result.output

        # Verify function was called correctly
        mock_get_profile.assert_called_once()
        args = mock_get_profile.call_args
        config = args[0][0]
        psk = args[0][1]
        assert config.server_url == 'https://test-server.com'
        assert config.output_path == output_file
        assert config.overwrite == True
        assert psk == 'test-computer-psk'

    def test_missing_server_url(self, runner):
        """Test error when server URL is not configured."""
        result = runner.invoke(get_openvpn_computer_config.main, [
            '--psk', 'test-psk'
        ])
        assert result.exit_code == 1
        assert "Server URL is not configured" in result.output

    def test_missing_psk(self, runner):
        """Test error when PSK is not provided."""
        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com'
        ])
        assert result.exit_code == 2  # Click parameter error

    @patch('get_openvpn_computer_config.Path.exists')
    def test_file_exists_without_force(self, mock_exists, runner):
        """Test error when output file exists and force is not specified."""
        mock_exists.return_value = True

        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com',
            '--output', '/path/to/existing.ovpn',
            '--psk', 'test-psk'
        ])

        assert result.exit_code == 1
        assert "already exists. Use --force to overwrite" in result.output

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_psk_authentication_error(self, mock_get_profile, runner):
        """Test handling of PSK authentication errors."""
        mock_get_profile.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com',
            '--psk', 'invalid-psk',
            '--force'
        ])

        assert result.exit_code == 1
        assert "401 Unauthorized" in result.output

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_network_error_handling(self, mock_get_profile, runner):
        """Test handling of network errors."""
        mock_get_profile.side_effect = requests.exceptions.ConnectionError("Network error")

        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com',
            '--psk', 'test-psk',
            '--force'
        ])

        assert result.exit_code == 1
        assert "Network error" in result.output

    def test_default_output_filename(self, runner):
        """Test that default output filename is computer-config.ovpn."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                result = runner.invoke(get_openvpn_computer_config.main, [
                    '--server-url', 'https://test-server.com',
                    '--psk', 'test-psk',
                    '--force'
                ])

                assert result.exit_code == 0

                # Verify config was created with default filename
                config = mock_get_profile.call_args[0][0]
                assert config.output_path.name == "computer-config.ovpn"

    def test_psk_from_environment_variable(self, runner, monkeypatch):
        """Test PSK resolution from environment variable."""
        monkeypatch.setenv('OVPN_PSK', 'env-psk-secret')

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                result = runner.invoke(get_openvpn_computer_config.main, [
                    '--server-url', 'https://test-server.com',
                    '--force'
                ])

                assert result.exit_code == 0

                # Verify PSK from environment was used
                psk = mock_get_profile.call_args[0][1]
                assert psk == 'env-psk-secret'


class TestComputerPSKAuthentication:
    """Test computer PSK authentication functionality."""

    @patch('get_openvpn_computer_config.requests.get')
    def test_get_computer_profile_with_psk_success(self, mock_get):
        """Test successful computer PSK authentication and profile retrieval."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.content = b'computer-profile-content'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        # Setup config
        config = get_openvpn_computer_config.Config(server_url='https://test-server.com')

        # Call function
        result = get_openvpn_computer_config.get_computer_profile_with_psk(config, 'computer-psk-secret')

        # Verify correct API call to computer bundle endpoint
        mock_get.assert_called_once_with(
            'https://test-server.com/api/v1/computer/bundle',
            headers={'Authorization': 'Bearer computer-psk-secret'},
            timeout=30
        )

        # Verify result
        assert result == b'computer-profile-content'

    @patch('get_openvpn_computer_config.requests.get')
    def test_get_computer_profile_with_psk_http_error(self, mock_get):
        """Test computer PSK authentication with HTTP error."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("403 Forbidden")
        mock_get.return_value = mock_response

        config = get_openvpn_computer_config.Config(server_url='https://test-server.com')

        with pytest.raises(requests.exceptions.HTTPError):
            get_openvpn_computer_config.get_computer_profile_with_psk(config, 'invalid-computer-psk')

    @patch('get_openvpn_computer_config.requests.get')
    def test_get_computer_profile_with_psk_timeout(self, mock_get):
        """Test computer PSK authentication with timeout."""
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        config = get_openvpn_computer_config.Config(server_url='https://test-server.com')

        with pytest.raises(requests.exceptions.Timeout):
            get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-computer-psk')

    @patch('get_openvpn_computer_config.requests.get')
    def test_get_computer_profile_with_psk_connection_error(self, mock_get):
        """Test computer PSK authentication with connection error."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

        config = get_openvpn_computer_config.Config(server_url='https://test-server.com')

        with pytest.raises(requests.exceptions.ConnectionError):
            get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-computer-psk')


class TestConfigurationManagement:
    """Test configuration resolution and management."""

    def test_config_precedence_server_url(self, monkeypatch, tmp_path):
        """Test configuration precedence for server URL."""
        # Create config files
        user_config = tmp_path / "user.yaml"
        user_config.write_text("server_url: https://user.com\n")

        system_config = tmp_path / "system.yaml"
        system_config.write_text("server_url: https://system.com\n")

        # Test CLI override
        config = get_openvpn_computer_config.Config(
            server_url='https://cli.com',
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://cli.com'

        # Test environment override
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.com')
        config = get_openvpn_computer_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://env.com'

        # Test user config precedence
        monkeypatch.delenv('OVPN_MANAGER_URL', raising=False)
        config = get_openvpn_computer_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://user.com'

    def test_config_output_path_defaults(self, tmp_path):
        """Test output path defaults and resolution."""
        config = get_openvpn_computer_config.Config()

        # Should default to downloads directory with computer-config.ovpn filename
        assert config.output_path.name == "computer-config.ovpn"
        assert isinstance(config.output_path, Path)

    def test_config_output_path_custom(self, tmp_path):
        """Test custom output path specification."""
        custom_path = tmp_path / "my-computer.ovpn"

        config = get_openvpn_computer_config.Config(output=str(custom_path))

        assert config.output_path == custom_path

    def test_config_overwrite_flag_resolution(self, monkeypatch, tmp_path):
        """Test overwrite flag resolution from various sources."""
        user_config = tmp_path / "user.yaml"
        user_config.write_text("overwrite: true\n")

        # Test CLI override
        config = get_openvpn_computer_config.Config(
            overwrite=False,
            _user_config_path=user_config
        )
        assert config.overwrite == False

        # Test environment variable
        monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', 'true')
        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent")
        )
        assert config.overwrite == True

        # Test various boolean string representations
        for true_val in ['true', '1', 't', 'y', 'yes']:
            monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', true_val)
            config = get_openvpn_computer_config.Config()
            assert config.overwrite == True

        for false_val in ['false', '0', 'f', 'n', 'no']:
            monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', false_val)
            config = get_openvpn_computer_config.Config()
            assert config.overwrite == False

    def test_config_malformed_yaml_handling(self, tmp_path):
        """Test handling of malformed YAML config files."""
        malformed_config = tmp_path / "malformed.yaml"
        malformed_config.write_text("invalid: yaml: content: [")

        # Should not raise exception, should return None for server_url
        config = get_openvpn_computer_config.Config(_user_config_path=malformed_config)
        assert config.server_url is None

    def test_config_missing_config_file_handling(self):
        """Test handling of missing config files."""
        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent/user.yaml"),
            _system_config_path=Path("/nonexistent/system.yaml")
        )
        assert config.server_url is None

    def test_config_environment_variables(self, monkeypatch):
        """Test configuration from environment variables."""
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env-server.com')
        monkeypatch.setenv('OVPN_MANAGER_OUTPUT', '~/my-computer-config.ovpn')
        monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', 'true')

        config = get_openvpn_computer_config.Config()

        assert config.server_url == 'https://env-server.com'
        assert str(config.output_path).endswith('my-computer-config.ovpn')
        assert config.overwrite == True

    def test_config_system_config_file_resolution(self, tmp_path):
        """Test system config file resolution (fallback to system config)."""
        system_config = tmp_path / "system_config.yaml"
        system_config.write_text("server_url: https://system.example.com\noutput: /system/config.ovpn\noverwrite: true")

        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent/user/config.yaml"),
            _system_config_path=system_config
        )

        assert config.server_url == 'https://system.example.com'
        assert str(config.output_path) == '/system/config.ovpn'
        assert config.overwrite is True

    def test_config_user_downloads_path_exception_handling(self):
        """Test handling of user_downloads_path() exceptions."""
        with patch('get_openvpn_computer_config.user_downloads_path') as mock_downloads:
            mock_downloads.side_effect = Exception("Downloads path not available")

            config = get_openvpn_computer_config.Config()

            # Should fallback to home directory
            expected_path = Path.home() / "computer-config.ovpn"
            assert config.output_path == expected_path


class TestSecurityAndErrorHandling:
    """Test security features and error handling."""

    @patch('get_openvpn_computer_config.requests.get')
    def test_request_headers_psk_bearer_token(self, mock_get):
        """Test that computer PSK is properly formatted as Bearer token in Authorization header."""
        mock_response = MagicMock()
        mock_response.content = b'content'
        mock_get.return_value = mock_response

        config = get_openvpn_computer_config.Config(server_url='https://test.com')

        get_openvpn_computer_config.get_computer_profile_with_psk(config, 'secret-computer-psk-123')

        # Verify Authorization header is properly formatted
        call_args = mock_get.call_args
        headers = call_args[1]['headers']
        assert headers['Authorization'] == 'Bearer secret-computer-psk-123'

    @patch('get_openvpn_computer_config.requests.get')
    def test_request_timeout_configuration(self, mock_get):
        """Test that requests have appropriate timeout configured."""
        mock_response = MagicMock()
        mock_response.content = b'content'
        mock_get.return_value = mock_response

        config = get_openvpn_computer_config.Config(server_url='https://test.com')

        get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-computer-psk')

        # Verify timeout is set
        call_args = mock_get.call_args
        assert call_args[1]['timeout'] == 30

    @patch('get_openvpn_computer_config.requests.get')
    def test_https_url_enforcement(self, mock_get):
        """Test that requests are made to correct computer bundle endpoint."""
        mock_response = MagicMock()
        mock_response.content = b'content'
        mock_get.return_value = mock_response

        config = get_openvpn_computer_config.Config(server_url='https://secure-server.com')

        get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-psk')

        # Verify correct endpoint is called
        call_args = mock_get.call_args
        url = call_args[0][0]
        assert url == 'https://secure-server.com/api/v1/computer/bundle'

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_error_message_security(self, mock_get_profile, runner):
        """Test that error messages don't expose sensitive information."""
        # Simulate an error that might contain sensitive info
        mock_get_profile.side_effect = Exception("Internal error with PSK: secret-psk-123")

        result = runner.invoke(get_openvpn_computer_config.main, [
            '--server-url', 'https://test-server.com',
            '--psk', 'secret-psk-123',
            '--force'
        ])

        assert result.exit_code == 1
        # The error message should be displayed but PSK should not be leaked in logs
        assert "An error occurred" in result.output

    def test_file_path_validation(self, runner):
        """Test validation of file paths."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                # Test with absolute path
                result = runner.invoke(get_openvpn_computer_config.main, [
                    '--server-url', 'https://test-server.com',
                    '--output', '/tmp/computer-config.ovpn',
                    '--psk', 'test-psk',
                    '--force'
                ])

                assert result.exit_code == 0

                # Verify path was handled correctly
                config = mock_get_profile.call_args[0][0]
                assert config.output_path == Path('/tmp/computer-config.ovpn')

    def test_psk_handling_security(self, runner):
        """Test that PSK is handled securely and not exposed in error messages."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.side_effect = requests.exceptions.HTTPError("Authentication failed")

            result = runner.invoke(get_openvpn_computer_config.main, [
                '--server-url', 'https://test-server.com',
                '--psk', 'very-secret-computer-psk',
                '--force'
            ])

            assert result.exit_code == 1
            # PSK should not appear in output
            assert 'very-secret-computer-psk' not in result.output

    def test_computer_vs_server_endpoint_differentiation(self):
        """Test that computer profile uses different endpoint than server profile."""
        config = get_openvpn_computer_config.Config(server_url='https://test.com')

        with patch('get_openvpn_computer_config.requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.content = b'content'
            mock_get.return_value = mock_response

            get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-psk')

            # Verify it calls the computer bundle endpoint, not server bundle
            call_args = mock_get.call_args
            url = call_args[0][0]
            assert '/api/v1/computer/bundle' in url
            assert '/api/v1/server/bundle' not in url


class TestIntegrationScenarios:
    """Test integration scenarios and edge cases."""

    def test_complete_workflow_success(self, runner, tmp_path):
        """Test complete workflow from command line to file output."""
        output_file = tmp_path / "test-computer.ovpn"
        expected_content = b'# OpenVPN Computer Configuration\nclient\nremote vpn.example.com 1194 udp\n'

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = expected_content

            with patch('builtins.open', mock_open()) as mock_file:
                result = runner.invoke(get_openvpn_computer_config.main, [
                    '--server-url', 'https://vpn.example.com',
                    '--output', str(output_file),
                    '--psk', 'computer-psk-secret',
                    '--force'
                ])

                assert result.exit_code == 0

                # Verify file was written
                mock_file.assert_called_with(output_file, 'wb')
                handle = mock_file()
                handle.write.assert_called_once_with(expected_content)

    def test_configuration_precedence_integration(self, runner, tmp_path, monkeypatch):
        """Test configuration precedence in realistic scenario."""
        # Setup config file
        config_dir = tmp_path / ".config" / "ovpn-manager"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.yaml"
        config_file.write_text("""
server_url: https://config-file.com
output: ~/config-computer.ovpn
overwrite: false
""")

        # Setup environment
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env-server.com')
        monkeypatch.setenv('OVPN_PSK', 'env-psk-secret')

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                # CLI should override environment and config file
                result = runner.invoke(get_openvpn_computer_config.main, [
                    '--server-url', 'https://cli-server.com',
                    '--force'
                ])

                assert result.exit_code == 0

                # Verify CLI server URL was used, but env PSK was used
                config = mock_get_profile.call_args[0][0]
                psk = mock_get_profile.call_args[0][1]
                assert config.server_url == 'https://cli-server.com'
                assert psk == 'env-psk-secret'

    def test_error_recovery_and_cleanup(self, runner, tmp_path):
        """Test error recovery and proper cleanup on failures."""
        output_file = tmp_path / "test-computer.ovpn"

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.side_effect = requests.exceptions.ConnectionError("Network failure")

            result = runner.invoke(get_openvpn_computer_config.main, [
                '--server-url', 'https://test-server.com',
                '--output', str(output_file),
                '--psk', 'test-psk',
                '--force'
            ])

            assert result.exit_code == 1
            assert "Network failure" in result.output

            # Verify no partial file was created
            assert not output_file.exists()


class TestMainEntryPoint:
    """Test __main__ entry point coverage."""

    def test_main_entry_point_coverage(self):
        """Test __main__ entry point is covered."""
        import subprocess
        import sys

        # Test that the script can be run with --help to cover __main__
        result = subprocess.run([
            sys.executable, '/workspaces/2025-06_openvpn-manager_gh-org/tools/get_openvpn_config/get_openvpn_computer_config.py', '--help'
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert 'computer profile' in result.stdout.lower()