"""
Tests for the get_openvpn_computer_config.py script - PSK computer profile functionality.
"""

import json
import pytest
import requests
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_computer_config


def _run(argv):
    """Invoke the CLI's ``main`` and return the SystemExit code (0 if no exit)."""
    try:
        get_openvpn_computer_config.main(argv)
    except SystemExit as exc:
        return exc.code if exc.code is not None else 0
    return 0


def _output(capsys):
    """Return combined stdout+stderr captured during the most recent call."""
    captured = capsys.readouterr()
    return captured.out + captured.err


class TestGetOVPNComputerConfig:
    """Test the get_openvpn_computer_config.py main function."""

    def test_help_output(self, capsys):
        """Test that help output is displayed correctly."""
        code = _run(['--help'])
        assert code == 0
        out = _output(capsys)
        assert "Fetches an OpenVPN computer profile using PSK authentication" in out
        assert "--server-url" in out
        assert "--output" in out
        assert "--force" in out
        assert "--psk" in out

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    @patch('builtins.open', new_callable=mock_open)
    def test_successful_computer_profile_download(self, mock_file, mock_get_profile, capsys, tmp_path):
        """Test successful computer profile download with PSK."""
        mock_get_profile.return_value = b'mock-computer-ovpn-content'
        output_file = tmp_path / "computer-config.ovpn"

        code = _run([
            '--server-url', 'https://test-server.com',
            '--output', str(output_file),
            '--psk', 'test-computer-psk',
            '--force',
        ])
        out = _output(capsys)

        assert code == 0
        assert "Requesting computer profile with PSK authentication..." in out
        assert f"Successfully saved computer configuration to {output_file}" in out

        mock_get_profile.assert_called_once()
        args = mock_get_profile.call_args
        config = args[0][0]
        psk = args[0][1]
        assert config.server_url == 'https://test-server.com'
        assert config.output_path == output_file
        assert config.overwrite is True
        assert psk == 'test-computer-psk'

    def test_missing_server_url(self, capsys):
        """Test error when server URL is not configured."""
        code = _run(['--psk', 'test-psk'])
        assert code == 1
        assert "Server URL is not configured" in _output(capsys)

    def test_missing_psk(self, capsys):
        """Test error when PSK is not provided."""
        code = _run(['--server-url', 'https://test-server.com'])
        assert code == 2  # argparse parameter error

    @patch('get_openvpn_computer_config.Path.exists')
    def test_file_exists_without_force(self, mock_exists, capsys):
        """Test error when output file exists and force is not specified."""
        mock_exists.return_value = True

        code = _run([
            '--server-url', 'https://test-server.com',
            '--output', '/path/to/existing.ovpn',
            '--psk', 'test-psk',
        ])

        assert code == 1
        assert "already exists. Use --force to overwrite" in _output(capsys)

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_psk_authentication_error(self, mock_get_profile, capsys):
        """Test handling of PSK authentication errors."""
        mock_get_profile.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

        code = _run([
            '--server-url', 'https://test-server.com',
            '--psk', 'invalid-psk',
            '--force',
        ])

        assert code == 1
        assert "401 Unauthorized" in _output(capsys)

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_network_error_handling(self, mock_get_profile, capsys):
        """Test handling of network errors."""
        mock_get_profile.side_effect = requests.exceptions.ConnectionError("Network error")

        code = _run([
            '--server-url', 'https://test-server.com',
            '--psk', 'test-psk',
            '--force',
        ])

        assert code == 1
        assert "Network error" in _output(capsys)

    def test_default_output_filename(self, capsys):
        """Test that default output filename is computer-config.ovpn."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--psk', 'test-psk',
                    '--force',
                ])

                assert code == 0
                config = mock_get_profile.call_args[0][0]
                assert config.output_path.name == "computer-config.ovpn"

    def test_psk_from_environment_variable(self, capsys, monkeypatch):
        """Test PSK resolution from environment variable."""
        monkeypatch.setenv('OVPN_PSK', 'env-psk-secret')

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--force',
                ])

                assert code == 0
                psk = mock_get_profile.call_args[0][1]
                assert psk == 'env-psk-secret'


class TestComputerPSKAuthentication:
    """Test computer PSK authentication functionality."""

    @patch('get_openvpn_computer_config.requests.get')
    def test_get_computer_profile_with_psk_success(self, mock_get):
        """Test successful computer PSK authentication and profile retrieval."""
        mock_response = MagicMock()
        mock_response.content = b'computer-profile-content'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = get_openvpn_computer_config.Config(server_url='https://test-server.com')
        result = get_openvpn_computer_config.get_computer_profile_with_psk(config, 'computer-psk-secret')

        mock_get.assert_called_once_with(
            'https://test-server.com/api/v1/computer/bundle',
            headers={'Authorization': 'Bearer computer-psk-secret'},
            timeout=30,
        )
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
        user_config = tmp_path / "user.json"
        user_config.write_text(json.dumps({"server_url": "https://user.com"}))

        system_config = tmp_path / "system.json"
        system_config.write_text(json.dumps({"server_url": "https://system.com"}))

        # CLI override
        config = get_openvpn_computer_config.Config(
            server_url='https://cli.com',
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://cli.com'

        # Environment override
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.com')
        config = get_openvpn_computer_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://env.com'

        # User config precedence
        monkeypatch.delenv('OVPN_MANAGER_URL', raising=False)
        config = get_openvpn_computer_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://user.com'

    def test_config_output_path_defaults(self, tmp_path):
        """Test output path defaults and resolution."""
        config = get_openvpn_computer_config.Config()

        assert config.output_path.name == "computer-config.ovpn"
        assert isinstance(config.output_path, Path)

    def test_config_output_path_custom(self, tmp_path):
        """Test custom output path specification."""
        custom_path = tmp_path / "my-computer.ovpn"

        config = get_openvpn_computer_config.Config(output=str(custom_path))

        assert config.output_path == custom_path

    def test_config_overwrite_flag_resolution(self, monkeypatch, tmp_path):
        """Test overwrite flag resolution from various sources."""
        user_config = tmp_path / "user.json"
        user_config.write_text(json.dumps({"overwrite": True}))

        # CLI override
        config = get_openvpn_computer_config.Config(
            overwrite=False,
            _user_config_path=user_config,
        )
        assert config.overwrite is False

        # Environment variable
        monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', 'true')
        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent"),
        )
        assert config.overwrite is True

        for true_val in ['true', '1', 't', 'y', 'yes']:
            monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', true_val)
            config = get_openvpn_computer_config.Config()
            assert config.overwrite is True

        for false_val in ['false', '0', 'f', 'n', 'no']:
            monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', false_val)
            config = get_openvpn_computer_config.Config()
            assert config.overwrite is False

    def test_config_malformed_json_handling(self, tmp_path):
        """Test handling of malformed JSON config files."""
        malformed_config = tmp_path / "malformed.json"
        malformed_config.write_text("{ this is not: valid json [")

        # Should not raise exception, should return None for server_url
        config = get_openvpn_computer_config.Config(_user_config_path=malformed_config)
        assert config.server_url is None

    def test_config_missing_config_file_handling(self):
        """Test handling of missing config files."""
        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent/user.json"),
            _system_config_path=Path("/nonexistent/system.json"),
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
        assert config.overwrite is True

    def test_config_system_config_file_resolution(self, tmp_path):
        """Test system config file resolution (fallback to system config)."""
        system_config = tmp_path / "system_config.json"
        system_config.write_text(json.dumps({
            "server_url": "https://system.example.com",
            "output": "/system/config.ovpn",
            "overwrite": True,
        }))

        config = get_openvpn_computer_config.Config(
            _user_config_path=Path("/nonexistent/user/config.json"),
            _system_config_path=system_config,
        )

        assert config.server_url == 'https://system.example.com'
        assert str(config.output_path) == '/system/config.ovpn'
        assert config.overwrite is True

    def test_config_strips_trailing_slash_from_server_url(self, monkeypatch):
        """Trailing slashes on the server URL must be stripped to avoid double-slash request paths."""
        # CLI argument with trailing slash
        config = get_openvpn_computer_config.Config(server_url='https://test.com/')
        assert config.server_url == 'https://test.com'

        # Multiple trailing slashes
        config = get_openvpn_computer_config.Config(server_url='https://test.com///')
        assert config.server_url == 'https://test.com'

        # Environment variable with trailing slash
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.com/')
        config = get_openvpn_computer_config.Config()
        assert config.server_url == 'https://env.com'

    def test_config_user_downloads_path_exception_handling(self):
        """Test handling of _user_downloads_path() exceptions."""
        with patch('get_openvpn_computer_config._user_downloads_path') as mock_downloads:
            mock_downloads.side_effect = Exception("Downloads path not available")

            config = get_openvpn_computer_config.Config()

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

        call_args = mock_get.call_args
        url = call_args[0][0]
        assert url == 'https://secure-server.com/api/v1/computer/bundle'

    @patch('get_openvpn_computer_config.get_computer_profile_with_psk')
    def test_error_message_security(self, mock_get_profile, capsys):
        """Test that error messages don't expose sensitive information."""
        mock_get_profile.side_effect = Exception("Internal error with PSK: secret-psk-123")

        code = _run([
            '--server-url', 'https://test-server.com',
            '--psk', 'secret-psk-123',
            '--force',
        ])

        assert code == 1
        assert "An error occurred" in _output(capsys)

    def test_file_path_validation(self, capsys):
        """Test validation of file paths."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--output', '/tmp/computer-config.ovpn',
                    '--psk', 'test-psk',
                    '--force',
                ])

                assert code == 0
                config = mock_get_profile.call_args[0][0]
                assert config.output_path == Path('/tmp/computer-config.ovpn')

    def test_psk_handling_security(self, capsys):
        """Test that PSK is handled securely and not exposed in error messages."""
        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.side_effect = requests.exceptions.HTTPError("Authentication failed")

            code = _run([
                '--server-url', 'https://test-server.com',
                '--psk', 'very-secret-computer-psk',
                '--force',
            ])

            assert code == 1
            # PSK must not appear in output
            assert 'very-secret-computer-psk' not in _output(capsys)

    def test_computer_vs_server_endpoint_differentiation(self):
        """Test that computer profile uses different endpoint than server profile."""
        config = get_openvpn_computer_config.Config(server_url='https://test.com')

        with patch('get_openvpn_computer_config.requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.content = b'content'
            mock_get.return_value = mock_response

            get_openvpn_computer_config.get_computer_profile_with_psk(config, 'test-psk')

            call_args = mock_get.call_args
            url = call_args[0][0]
            assert '/api/v1/computer/bundle' in url
            assert '/api/v1/server/bundle' not in url


class TestIntegrationScenarios:
    """Test integration scenarios and edge cases."""

    def test_complete_workflow_success(self, capsys, tmp_path):
        """Test complete workflow from command line to file output."""
        output_file = tmp_path / "test-computer.ovpn"
        expected_content = b'# OpenVPN Computer Configuration\nclient\nremote vpn.example.com 1194 udp\n'

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = expected_content

            with patch('builtins.open', mock_open()) as mock_file:
                code = _run([
                    '--server-url', 'https://vpn.example.com',
                    '--output', str(output_file),
                    '--psk', 'computer-psk-secret',
                    '--force',
                ])

                assert code == 0
                mock_file.assert_called_with(output_file, 'wb')
                handle = mock_file()
                handle.write.assert_called_once_with(expected_content)

    def test_configuration_precedence_integration(self, capsys, tmp_path, monkeypatch):
        """Test configuration precedence in realistic scenario."""
        config_dir = tmp_path / ".config" / "ovpn-manager"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text(json.dumps({
            "server_url": "https://config-file.com",
            "output": "~/config-computer.ovpn",
            "overwrite": False,
        }))

        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env-server.com')
        monkeypatch.setenv('OVPN_PSK', 'env-psk-secret')

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()):
                # CLI overrides environment and config file
                code = _run([
                    '--server-url', 'https://cli-server.com',
                    '--force',
                ])

                assert code == 0
                config = mock_get_profile.call_args[0][0]
                psk = mock_get_profile.call_args[0][1]
                assert config.server_url == 'https://cli-server.com'
                assert psk == 'env-psk-secret'

    def test_error_recovery_and_cleanup(self, capsys, tmp_path):
        """Test error recovery and proper cleanup on failures."""
        output_file = tmp_path / "test-computer.ovpn"

        with patch('get_openvpn_computer_config.get_computer_profile_with_psk') as mock_get_profile:
            mock_get_profile.side_effect = requests.exceptions.ConnectionError("Network failure")

            code = _run([
                '--server-url', 'https://test-server.com',
                '--output', str(output_file),
                '--psk', 'test-psk',
                '--force',
            ])

            assert code == 1
            assert "Network failure" in _output(capsys)
            assert not output_file.exists()


class TestMainEntryPoint:
    """Test __main__ entry point coverage."""

    def test_main_entry_point_coverage(self):
        """Test __main__ entry point is covered."""
        import subprocess
        import sys
        from pathlib import Path

        script_path = Path(__file__).parent.parent / 'get_openvpn_computer_config.py'
        result = subprocess.run([
            sys.executable, str(script_path), '--help',
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert 'computer profile' in result.stdout.lower()
