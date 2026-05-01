"""
Tests for the get_openvpn_profile.py script - OIDC profile functionality.
"""

import io
import json
import socket
import sys
import pytest
import requests
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_profile


def _run(argv):
    """Invoke the CLI's ``main`` and return the SystemExit code (0 if no exit)."""
    try:
        get_openvpn_profile.main(argv)
    except SystemExit as exc:
        return exc.code if exc.code is not None else 0
    return 0


def _output(capsys):
    """Return combined stdout+stderr captured during the most recent call."""
    captured = capsys.readouterr()
    return captured.out + captured.err


class TestGetOVPNProfile:
    """Test the get_openvpn_profile.py main function."""

    def test_help_output(self, capsys):
        """Test that help output is displayed correctly."""
        code = _run(['--help'])
        assert code == 0
        out = _output(capsys)
        assert "Fetches an OpenVPN user profile using the browser-based OIDC login flow" in out
        assert "--server-url" in out
        assert "--output" in out
        assert "--force" in out
        assert "--options" in out
        assert "--output-auth-url" in out

    @patch('get_openvpn_profile.get_profile_with_oidc')
    @patch('get_openvpn_profile.requests.get')
    @patch('builtins.open', new_callable=mock_open)
    def test_successful_profile_download(self, mock_file, mock_health_check, mock_get_profile, capsys, tmp_path):
        """Test successful profile download with OIDC."""
        mock_get_profile.return_value = b'mock-ovpn-content'
        mock_health_check.return_value.raise_for_status = MagicMock()

        output_file = tmp_path / "test.ovpn"

        code = _run([
            '--server-url', 'https://test-server.com',
            '--output', str(output_file),
            '--force',
        ])
        out = _output(capsys)

        assert code == 0
        assert "Starting OIDC login flow..." in out
        assert f"Successfully saved configuration to {output_file}" in out

        mock_get_profile.assert_called_once()
        args = mock_get_profile.call_args
        config = args[0][0]
        assert config.server_url == 'https://test-server.com'
        assert config.output_path == output_file
        assert config.overwrite is True

    def test_missing_server_url(self, capsys):
        """Test error when server URL is not configured."""
        code = _run([])
        assert code == 1
        assert "Server URL is not configured" in _output(capsys)

    @patch('get_openvpn_profile.Path.exists')
    def test_file_exists_without_force(self, mock_exists, capsys):
        """Test error when output file exists and force is not specified."""
        mock_exists.return_value = True

        code = _run([
            '--server-url', 'https://test-server.com',
            '--output', '/path/to/existing.ovpn',
        ])

        assert code == 1
        assert "already exists. Use --force to overwrite" in _output(capsys)

    @patch('get_openvpn_profile.get_profile_with_oidc')
    @patch('get_openvpn_profile.requests.get')
    def test_authentication_timeout_error(self, mock_health, mock_get_profile, capsys):
        """Test handling of authentication timeout."""
        mock_health.return_value.raise_for_status = MagicMock()
        mock_get_profile.side_effect = Exception("Authentication timed out.")

        code = _run([
            '--server-url', 'https://test-server.com',
            '--force',
        ])

        assert code == 1
        assert "Authentication timed out" in _output(capsys)

    @patch('get_openvpn_profile.get_profile_with_oidc')
    @patch('get_openvpn_profile.requests.get')
    def test_network_error_handling(self, mock_requests_get, mock_get_profile, capsys):
        """Test handling of network errors."""
        mock_requests_get.side_effect = requests.exceptions.ConnectionError("Network error")

        code = _run([
            '--server-url', 'https://test-server.com',
            '--force',
        ])

        assert code == 1
        assert "Network error" in _output(capsys)

    @patch('get_openvpn_profile.requests.get')
    def test_server_connectivity_error(self, mock_get, capsys):
        """Test handling of server connectivity check failure."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")

        code = _run([
            '--server-url', 'https://unreachable-server.com',
            '--force',
        ])

        assert code == 1
        out = _output(capsys)
        assert "Cannot connect to server" in out
        assert "Connection refused" in out

    def test_options_parameter_passing(self, capsys):
        """Test that options parameter is passed correctly."""
        with patch('get_openvpn_profile.get_profile_with_oidc') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()), \
                 patch('get_openvpn_profile.requests.get') as mock_health_check:
                mock_health_check.return_value.raise_for_status = MagicMock()

                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--options', 'tcp,udp',
                    '--force',
                ])

                assert code == 0
                config = mock_get_profile.call_args[0][0]
                assert config.options == 'tcp,udp'

    def test_output_auth_url_parameter(self, capsys):
        """Test that output-auth-url parameter is passed correctly."""
        with patch('get_openvpn_profile.get_profile_with_oidc') as mock_get_profile:
            mock_get_profile.return_value = b'content'

            with patch('builtins.open', mock_open()), \
                 patch('get_openvpn_profile.requests.get') as mock_health_check:
                mock_health_check.return_value.raise_for_status = MagicMock()

                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--output-auth-url', 'stderr',
                    '--force',
                ])

                assert code == 0
                assert mock_get_profile.call_args[0][1] == 'stderr'


class TestOIDCAuthentication:
    """Test OIDC authentication flow components."""

    def test_find_free_port(self):
        """Test that _find_free_port returns a valid port."""
        port = get_openvpn_profile._find_free_port()
        assert isinstance(port, int)
        assert 1024 <= port <= 65535

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            result = s.connect_ex(('127.0.0.1', port))
            assert result != 0

    @patch('get_openvpn_profile.webbrowser.open')
    @patch('get_openvpn_profile.HTTPServer')
    @patch('get_openvpn_profile.requests.get')
    def test_get_profile_with_oidc_success(self, mock_requests, mock_server, mock_browser):
        """Test successful OIDC authentication flow."""
        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance

        mock_response = MagicMock()
        mock_response.content = b'mock-profile-content'
        mock_requests.return_value = mock_response

        config = get_openvpn_profile.Config(server_url='https://test.com', options='tcp')

        get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

        try:
            result = get_openvpn_profile.get_profile_with_oidc(config)

            mock_browser.assert_called_once()
            call_args = mock_browser.call_args[0][0]
            assert 'https://test.com/auth/login' in call_args
            assert 'cli_port=' in call_args
            assert 'optionset=tcp' in call_args

            mock_requests.assert_called_once_with(
                'https://test.com/download?token=test-token',
                timeout=30,
            )

            assert result == b'mock-profile-content'

        finally:
            get_openvpn_profile._RECEIVED_TOKEN.clear()

    @patch('get_openvpn_profile.webbrowser.open')
    @patch('get_openvpn_profile.HTTPServer')
    def test_get_profile_with_oidc_timeout(self, mock_server, mock_browser):
        """Test OIDC authentication timeout."""
        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance

        config = get_openvpn_profile.Config(server_url='https://test.com')

        with patch('get_openvpn_profile.time.time') as mock_time:
            mock_time.side_effect = [0, 121]

            with pytest.raises(Exception) as exc_info:
                get_openvpn_profile.get_profile_with_oidc(config)

            assert "Authentication timed out" in str(exc_info.value)

    @patch('builtins.open', new_callable=mock_open)
    def test_output_auth_url_to_file(self, mock_file):
        """Test outputting auth URL to file instead of browser."""
        with patch('get_openvpn_profile.HTTPServer') as mock_server:
            mock_server_instance = MagicMock()
            mock_server.return_value = mock_server_instance

            config = get_openvpn_profile.Config(server_url='https://test.com')

            get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

            with patch('get_openvpn_profile.requests.get') as mock_requests:
                mock_response = MagicMock()
                mock_response.content = b'content'
                mock_requests.return_value = mock_response

                try:
                    get_openvpn_profile.get_profile_with_oidc(config, output_auth_url='/tmp/auth_url')

                    mock_file.assert_called_with('/tmp/auth_url', 'w')
                    handle = mock_file()
                    handle.write.assert_called_once()

                    written_url = handle.write.call_args[0][0]
                    assert 'https://test.com/auth/login' in written_url

                finally:
                    get_openvpn_profile._RECEIVED_TOKEN.clear()

    def test_output_auth_url_to_stderr(self):
        """Test outputting auth URL to stderr."""
        with patch('get_openvpn_profile.HTTPServer') as mock_server:
            mock_server_instance = MagicMock()
            mock_server.return_value = mock_server_instance

            get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

            with patch('get_openvpn_profile.requests.get') as mock_requests:
                mock_response = MagicMock()
                mock_response.content = b'content'
                mock_requests.return_value = mock_response

                with patch('builtins.open', mock_open()):
                    old_stderr = sys.stderr
                    captured_stderr = io.StringIO()
                    sys.stderr = captured_stderr

                    try:
                        config = get_openvpn_profile.Config(
                            server_url='https://test.com',
                            output='/tmp/test.ovpn',
                            overwrite=True,
                        )

                        get_openvpn_profile.get_profile_with_oidc(config, output_auth_url='stderr')

                        stderr_output = captured_stderr.getvalue()
                        assert 'AUTH_URL: https://test.com/auth/login' in stderr_output

                    finally:
                        sys.stderr = old_stderr
                        get_openvpn_profile._RECEIVED_TOKEN.clear()


class TestConfigurationManagement:
    """Test configuration resolution and management."""

    def test_config_precedence_server_url(self, monkeypatch, tmp_path):
        """Test configuration precedence for server URL."""
        user_config = tmp_path / "user.json"
        user_config.write_text(json.dumps({"server_url": "https://user.com"}))

        system_config = tmp_path / "system.json"
        system_config.write_text(json.dumps({"server_url": "https://system.com"}))

        # CLI override
        config = get_openvpn_profile.Config(
            server_url='https://cli.com',
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://cli.com'

        # Environment override
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.com')
        config = get_openvpn_profile.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://env.com'

    def test_config_output_path_defaults(self, tmp_path):
        """Test output path defaults and resolution."""
        config = get_openvpn_profile.Config()

        assert config.output_path.name == "config.ovpn"
        assert isinstance(config.output_path, Path)

    def test_config_overwrite_flag_resolution(self, monkeypatch, tmp_path):
        """Test overwrite flag resolution from various sources."""
        user_config = tmp_path / "user.json"
        user_config.write_text(json.dumps({"overwrite": True}))

        # CLI override
        config = get_openvpn_profile.Config(
            overwrite=False,
            _user_config_path=user_config,
        )
        assert config.overwrite is False

        # Environment variable
        monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', 'true')
        config = get_openvpn_profile.Config(
            _user_config_path=Path("/nonexistent"),
        )
        assert config.overwrite is True

        for true_val in ['true', '1', 't', 'y', 'yes']:
            monkeypatch.setenv('OVPN_MANAGER_OVERWRITE', true_val)
            config = get_openvpn_profile.Config()
            assert config.overwrite is True

    def test_config_user_config_file_resolution(self, tmp_path):
        """Test user config file resolution takes precedence over system config."""
        user_config = tmp_path / "user_config.json"
        user_config.write_text(json.dumps({
            "server_url": "https://user.example.com",
            "output": "/user/config.ovpn",
            "overwrite": False,
            "options": "udp",
        }))

        system_config = tmp_path / "system_config.json"
        system_config.write_text(json.dumps({
            "server_url": "https://system.example.com",
            "output": "/system/config.ovpn",
            "overwrite": True,
            "options": "tcp",
        }))

        config = get_openvpn_profile.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )

        assert config.server_url == 'https://user.example.com'
        assert str(config.output_path) == '/user/config.ovpn'
        assert config.overwrite is False
        assert config.options == 'udp'

    def test_config_system_config_file_resolution(self, tmp_path):
        """Test system config file resolution (fallback to system config)."""
        system_config = tmp_path / "system_config.json"
        system_config.write_text(json.dumps({
            "server_url": "https://system.example.com",
            "output": "/system/config.ovpn",
            "overwrite": True,
            "options": "tcp",
        }))

        config = get_openvpn_profile.Config(
            _user_config_path=Path("/nonexistent/user/config.json"),
            _system_config_path=system_config,
        )

        assert config.server_url == 'https://system.example.com'
        assert str(config.output_path) == '/system/config.ovpn'
        assert config.overwrite is True
        assert config.options == 'tcp'

    def test_config_user_downloads_path_exception_handling(self):
        """Test handling of _user_downloads_path() exceptions."""
        with patch('get_openvpn_profile._user_downloads_path') as mock_downloads:
            mock_downloads.side_effect = Exception("Downloads path not available")

            config = get_openvpn_profile.Config()

            expected_path = Path.home() / "config.ovpn"
            assert config.output_path == expected_path


class TestSecurityAndErrorHandling:
    """Test security features and error handling."""

    @patch('get_openvpn_profile.requests.get')
    @patch('get_openvpn_profile.HTTPServer')
    @patch('get_openvpn_profile.threading.Thread')
    @patch('get_openvpn_profile.webbrowser.open')
    def test_http_error_handling(self, mock_browser, mock_thread, mock_server, mock_requests):
        """Test handling of HTTP errors during download."""
        mock_requests.side_effect = requests.exceptions.HTTPError("404 Not Found")

        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        config = get_openvpn_profile.Config(server_url='https://test.com')

        get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

        try:
            with pytest.raises(requests.exceptions.HTTPError):
                get_openvpn_profile.get_profile_with_oidc(config)
        finally:
            get_openvpn_profile._RECEIVED_TOKEN.clear()

    @patch('get_openvpn_profile.requests.get')
    @patch('get_openvpn_profile.HTTPServer')
    @patch('get_openvpn_profile.threading.Thread')
    @patch('get_openvpn_profile.webbrowser.open')
    def test_connection_error_handling(self, mock_browser, mock_thread, mock_server, mock_requests):
        """Test handling of connection errors."""
        mock_requests.side_effect = requests.exceptions.ConnectionError("Connection failed")

        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        config = get_openvpn_profile.Config(server_url='https://test.com')

        get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

        try:
            with pytest.raises(requests.exceptions.ConnectionError):
                get_openvpn_profile.get_profile_with_oidc(config)
        finally:
            get_openvpn_profile._RECEIVED_TOKEN.clear()

    def test_malformed_config_file_handling(self, tmp_path):
        """Test handling of malformed JSON config files."""
        malformed_config = tmp_path / "malformed.json"
        malformed_config.write_text("{ this is not: valid json [")

        config = get_openvpn_profile.Config(_user_config_path=malformed_config)
        assert config.server_url is None

    def test_missing_config_file_handling(self):
        """Test handling of missing config files."""
        config = get_openvpn_profile.Config(
            _user_config_path=Path("/nonexistent/user.json"),
            _system_config_path=Path("/nonexistent/system.json"),
        )
        assert config.server_url is None

    @patch('get_openvpn_profile.requests.get')
    @patch('get_openvpn_profile.HTTPServer')
    @patch('get_openvpn_profile.threading.Thread')
    @patch('get_openvpn_profile.webbrowser.open')
    def test_request_timeout_handling(self, mock_browser, mock_thread, mock_server, mock_requests):
        """Test handling of request timeouts."""
        mock_requests.side_effect = requests.exceptions.Timeout("Request timed out")

        mock_server_instance = MagicMock()
        mock_server.return_value = mock_server_instance
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        config = get_openvpn_profile.Config(server_url='https://test.com')

        get_openvpn_profile._RECEIVED_TOKEN.append('test-token')

        try:
            with pytest.raises(requests.exceptions.Timeout):
                get_openvpn_profile.get_profile_with_oidc(config)
        finally:
            get_openvpn_profile._RECEIVED_TOKEN.clear()

    def test_callback_handler_token_extraction(self):
        """Test callback handler token extraction."""
        handler = object.__new__(get_openvpn_profile._CallbackHandler)
        handler.path = '/callback?token=test-token-123&other=param'

        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()

        get_openvpn_profile._RECEIVED_TOKEN.clear()

        try:
            handler.do_GET()

            assert len(get_openvpn_profile._RECEIVED_TOKEN) == 1
            assert get_openvpn_profile._RECEIVED_TOKEN[0] == 'test-token-123'

        finally:
            get_openvpn_profile._RECEIVED_TOKEN.clear()

    def test_callback_handler_no_token(self):
        """Test callback handler when no token is present."""
        handler = object.__new__(get_openvpn_profile._CallbackHandler)
        handler.path = '/callback?other=param'

        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()

        get_openvpn_profile._RECEIVED_TOKEN.clear()

        handler.do_GET()

        assert len(get_openvpn_profile._RECEIVED_TOKEN) == 0

    def test_callback_handler_log_message_coverage(self):
        """Test callback handler log_message method coverage."""
        handler = object.__new__(get_openvpn_profile._CallbackHandler)

        result = handler.log_message("Test format %s", "arg1")
        assert result is None


class TestMainEntryPoint:
    """Test __main__ entry point coverage."""

    def test_main_entry_point_coverage(self):
        """Test __main__ entry point is covered."""
        import subprocess
        import sys
        from pathlib import Path

        script_path = Path(__file__).parent.parent / 'get_openvpn_profile.py'
        result = subprocess.run([
            sys.executable, str(script_path), '--help',
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert 'oidc' in result.stdout.lower() or 'profile' in result.stdout.lower()
