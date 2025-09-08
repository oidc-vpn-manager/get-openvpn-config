import pytest
import requests
import time
import os
import tarfile
import tempfile
import io
from click.testing import CliRunner
from unittest.mock import MagicMock, patch
from pathlib import Path
from click import ClickException

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from get_openvpn_config import _RECEIVED_TOKEN, _CallbackHandler
from get_openvpn_config import *

@pytest.fixture
def runner():
    return CliRunner()

class TestConfigResolution:
    """Tests the logic of the Config class."""

    def test_precedence_order(self, monkeypatch, tmp_path):
        """Tests CLI > Env > User > System config precedence."""
        user_config_path = tmp_path / "user.yaml"
        user_config_path.write_text("server_url: http://user.config.com\n")
        system_config_path = tmp_path / "system.yaml"
        system_config_path.write_text("server_url: http://system.config.com\n")
        
        # 4. System config only
        cfg = Config(_user_config_path=Path("/dne"), _system_config_path=system_config_path)
        assert cfg.server_url == "http://system.config.com"

        # 3. User config overrides system
        cfg = Config(_user_config_path=user_config_path, _system_config_path=system_config_path)
        assert cfg.server_url == "http://user.config.com"

        # 2. Environment variable overrides user
        monkeypatch.setenv("OVPN_MANAGER_URL", "http://env.config.com")
        cfg = Config(_user_config_path=user_config_path, _system_config_path=system_config_path)
        assert cfg.server_url == "http://env.config.com"

        # 1. CLI flag overrides all
        cfg = Config(server_url="http://cli.config.com", _user_config_path=user_config_path, _system_config_path=system_config_path)
        assert cfg.server_url == "http://cli.config.com"

    def test_output_path_fallback(self, monkeypatch):
        """Tests the output path falls back to the home directory."""
        monkeypatch.setattr('get_openvpn_config.user_downloads_path', lambda: exec("raise Exception('No dir')"))
        cfg = Config()
        assert cfg.output_path == Path.home() / "config.ovpn"

    def test_bad_config_file_is_handled(self, tmp_path):
        """Tests that a corrupt YAML file is handled gracefully."""
        bad_config_path = tmp_path / "bad_config.yaml"
        bad_config_path.write_text("server_url: http://a.com\n[invalid syntax")
        
        cfg = Config(_user_config_path=bad_config_path)
        assert cfg.user_config == {}

class TestApiClientLogic:
    """Tests the API client functions."""
    
    @pytest.fixture
    def mock_config(self):
        config = MagicMock()
        config.server_url = "http://test.server"
        config.options = "default"
        return config

    @patch('get_openvpn_config.requests')
    def test_psk_http_error(self, mock_requests, mock_config):
        """Tests that an HTTP error raises the original exception."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError
        mock_requests.get.return_value = mock_response

        with pytest.raises(requests.exceptions.HTTPError):
            get_profile_with_psk(mock_config, 'test-psk')

    def test_oidc_callback_handler(self):
        """Tests that the callback handler correctly parses the token."""
        _RECEIVED_TOKEN.clear()
        mock_handler = MagicMock()
        mock_handler.path = "/callback?token=my-secret-token"
        _CallbackHandler.do_GET(mock_handler)
        assert _RECEIVED_TOKEN == ["my-secret-token"]
    
    def test_callback_handler_log_message(self):
        """Covers the no-op log_message for coverage."""
        mock_self = MagicMock()
        _CallbackHandler.log_message(mock_self, "test %s", "message")

    @patch('get_openvpn_config.threading.Thread')
    @patch('get_openvpn_config.HTTPServer')
    @patch('get_openvpn_config.webbrowser')
    @patch('get_openvpn_config.requests')
    def test_oidc_success(self, mock_requests, mock_webbrowser, mock_http_server, mock_thread, mock_config):
        """Tests the successful OIDC authentication flow."""
        # Arrange: Clear the global token list before the test
        _RECEIVED_TOKEN.clear()
        
        # Arrange: Simulate the callback server receiving a token after the thread starts
        def simulate_callback(*args):
            _RECEIVED_TOKEN.append("test-token")

        mock_thread.return_value.start.side_effect = simulate_callback
        
        # Arrange: Mock the final download call
        mock_response = MagicMock()
        mock_response.content = b"vpn-profile-content"
        mock_requests.get.return_value = mock_response

        # Act
        result = get_profile_with_oidc(mock_config)

        # Assert
        assert result == b"vpn-profile-content"
        mock_webbrowser.open.assert_called_once()
        mock_http_server.return_value.shutdown.assert_called_once()

    @patch('get_openvpn_config.time.time')
    @patch('get_openvpn_config.webbrowser')
    @patch('get_openvpn_config.HTTPServer')
    @patch('get_openvpn_config.threading.Thread')
    @patch('get_openvpn_config.time.sleep')
    def test_oidc_timeout(self, mock_sleep, mock_thread, mock_http, mock_webbrowser, mock_time, mock_config):
        """Tests that the OIDC flow raises a ClickException on timeout."""
        _RECEIVED_TOKEN.clear()
        # Make time.time() return values that simulate a timeout
        mock_time.side_effect = [1000, 1001, 1201]
        
        with pytest.raises(ClickException, match="Authentication timed out."):
            get_profile_with_oidc(mock_config)

    @patch('get_openvpn_config.click.echo')
    @patch('get_openvpn_config.threading.Thread')
    @patch('get_openvpn_config.HTTPServer')
    def test_oidc_output_auth_url_stderr(self, mock_http_server, mock_thread, mock_echo, mock_config):
        """Tests that output_auth_url='stderr' outputs URL to stderr instead of opening browser."""
        _RECEIVED_TOKEN.clear()
        
        # Let _find_free_port pick a random port - capture what it returns
        actual_port = None
        
        # Mock HTTPServer to capture the port being used
        original_http_server = HTTPServer
        def capture_port_http_server(address, handler):
            nonlocal actual_port
            actual_port = address[1]  # Capture the port
            return MagicMock()
        mock_http_server.side_effect = capture_port_http_server
        
        # Simulate callback receiving token immediately 
        def simulate_callback(*args):
            _RECEIVED_TOKEN.append("test-token")
        mock_thread.return_value.start.side_effect = simulate_callback
        
        with patch('get_openvpn_config.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.content = b"vpn-profile-content"
            mock_requests.get.return_value = mock_response
            
            # Act
            result = get_profile_with_oidc(mock_config, output_auth_url='stderr')
            
            # Assert
            assert result == b"vpn-profile-content"
            # Verify URL was echoed to stderr with the actual port that was used
            expected_url = f"{mock_config.server_url}/auth/login?cli_port={actual_port}&optionset={mock_config.options}"
            mock_echo.assert_called_once_with(f"AUTH_URL: {expected_url}", err=True)

    @patch('builtins.open', create=True)
    @patch('get_openvpn_config.threading.Thread')  
    @patch('get_openvpn_config.HTTPServer')
    def test_oidc_output_auth_url_file(self, mock_http_server, mock_thread, mock_open, mock_config):
        """Tests that output_auth_url with filename outputs URL to file instead of opening browser."""
        _RECEIVED_TOKEN.clear()
        
        # Simulate callback receiving token immediately
        def simulate_callback(*args):
            _RECEIVED_TOKEN.append("test-token")
        mock_thread.return_value.start.side_effect = simulate_callback
        
        # Capture the actual port being used
        actual_port = None
        def capture_port_http_server(address, handler):
            nonlocal actual_port
            actual_port = address[1]  # Capture the port
            return MagicMock()
        mock_http_server.side_effect = capture_port_http_server
        
        # Mock file writing
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        with patch('get_openvpn_config.requests') as mock_requests:
            mock_response = MagicMock()
            mock_response.content = b"vpn-profile-content" 
            mock_requests.get.return_value = mock_response
            
            # Act
            result = get_profile_with_oidc(mock_config, output_auth_url='/tmp/auth_url.txt')
            
            # Assert
            assert result == b"vpn-profile-content"
            # Verify file was opened and URL written with actual port
            mock_open.assert_called_once_with('/tmp/auth_url.txt', 'w')
            expected_url = f"{mock_config.server_url}/auth/login?cli_port={actual_port}&optionset={mock_config.options}"
            mock_file.write.assert_called_once_with(expected_url)

    @patch('get_openvpn_config.requests')
    def test_get_profile_with_psk_success(self, mock_requests, mock_config):
        """Tests the successful PSK profile retrieval."""
        mock_response = MagicMock()
        mock_response.content = b'tar file content'
        mock_requests.get.return_value = mock_response

        result = get_profile_with_psk(mock_config, 'psk')
        assert result == b'tar file content'

class TestCliLogic:
    """Tests the Click command functions."""
    
    @patch('get_openvpn_config.extract_server_files')
    @patch('get_openvpn_config.get_profile_with_psk')
    @patch('get_openvpn_config.Config')
    def test_psk_command_success(self, MockConfig, mock_get_profile, mock_extract, runner, tmp_path):
        target_dir = tmp_path / "openvpn"
        MockConfig.return_value.server_url = "http://test.server"
        mock_get_profile.return_value = b'tar content'
        mock_extract.return_value = {
            'cert_dir': target_dir / 'cert',
            'key_dir': target_dir / 'key', 
            'udp_dir': target_dir / 'udp-1194',
            'tcp_dir': target_dir / 'tcp-443'
        }
        
        result = runner.invoke(
            cli,
            ['get-psk-profile', '--psk', 'test-key', '--target-dir', str(target_dir)]
        )
        assert result.exit_code == 0
        assert "Successfully extracted" in result.output
        mock_extract.assert_called_once_with(b'tar content', target_dir)

    @patch('get_openvpn_config.Config')
    def test_file_exists_no_overwrite(self, MockConfig, runner, tmp_path):
        """Tests that the command fails if the target directory contains files without --force."""
        target_dir = tmp_path / "openvpn"
        target_dir.mkdir()
        (target_dir / "existing_file.txt").touch()
        MockConfig.return_value.server_url = "http://test.server"

        result = runner.invoke(
            cli,
            ['get-psk-profile', '--psk', 'p', '--target-dir', str(target_dir)]
        )
        assert result.exit_code == 1
        assert "contains files" in result.output

    @patch('get_openvpn_config.get_profile_with_oidc')
    @patch('get_openvpn_config.Config')
    def test_oidc_command_success(self, MockConfig, mock_get_profile, runner, tmp_path):
        """Tests the successful execution of the get-oidc-profile command."""
        output_file = tmp_path / "test.ovpn"
        MockConfig.return_value.server_url = "http://test.server"
        MockConfig.return_value.output_path = output_file
        MockConfig.return_value.overwrite = False
        mock_get_profile.return_value = b"oidc-data"

        result = runner.invoke(cli, ['get-oidc-profile'])
        
        assert result.exit_code == 0
        assert "Successfully saved" in result.output
        assert output_file.read_bytes() == b"oidc-data"

    @patch('get_openvpn_config.Config')
    def test_psk_command_missing_url(self, MockConfig, runner):
        """Tests that the PSK command fails if the server URL is not configured."""
        MockConfig.return_value.server_url = None

        result = runner.invoke(
            cli,
            ['get-psk-profile', '--psk', 'p']
        )
        assert result.exit_code == 1
        assert "Server URL is not configured" in result.output

    @patch('get_openvpn_config.Config')
    def test_oidc_command_generic_error(self, MockConfig, runner):
        """Tests that a generic exception is caught in the OIDC command."""
        MockConfig.side_effect = Exception("A generic error occurred")

        result = runner.invoke(cli, ['get-oidc-profile'])
        
        assert result.exit_code == 1
        assert "An error occurred: A generic error occurred" in result.output

class TestConfigArgumentHandling:
    """Tests the handling of direct CLI arguments in the Config class."""

    def test_output_path_from_cli_arg(self):
        """Tests that an explicit output path is used."""
        cfg = Config(output="~/my-test.ovpn")
        assert cfg.output_path == Path.home() / "my-test.ovpn"

    def test_overwrite_flag_from_cli_arg(self):
        """Tests that the overwrite flag is set to True via the CLI arg."""
        cfg = Config(overwrite=True)
        assert cfg.overwrite is True

    def test_overwrite_flag_from_env_var(self, monkeypatch):
        """Tests that the overwrite flag is set via an environment variable."""
        monkeypatch.setenv("OVPN_MANAGER_OVERWRITE", "yes")
        # Instantiate without the CLI flag
        cfg = Config()
        assert cfg.overwrite is True

class TestCliOidcEdgeCases:
    """Tests edge cases for the get-oidc-profile command."""

    @patch('get_openvpn_config.Config')
    def test_oidc_command_missing_url(self, MockConfig, runner):
        """Tests that the OIDC command fails if the server URL is not configured."""
        MockConfig.return_value.server_url = None
        
        result = runner.invoke(cli, ['get-oidc-profile'])
        
        assert result.exit_code == 1
        assert "Server URL is not configured" in result.output

    @patch('get_openvpn_config.Config')
    def test_oidc_command_file_exists_no_overwrite(self, MockConfig, runner, tmp_path):
        """Tests that the OIDC command fails if the output file exists without --force."""
        output_file = tmp_path / "test.ovpn"
        output_file.touch()
        
        MockConfig.return_value.server_url = "http://test.server"
        MockConfig.return_value.output_path = output_file
        MockConfig.return_value.overwrite = False

        result = runner.invoke(
            cli,
            ['get-oidc-profile', '--output', str(output_file)]
        )
        assert result.exit_code == 1
        assert "already exists" in result.output

class TestExtractServerFiles:
    """Tests the extract_server_files function."""
    
    def test_extract_server_files_success(self, tmp_path):
        """Tests successful extraction of tar file with various file types."""
        target_dir = tmp_path / "openvpn"
        
        # Create a test tar file with various file types
        with tempfile.NamedTemporaryFile() as temp_tar:
            with tarfile.open(temp_tar.name, 'w') as tar:
                # Add CA certificate
                ca_info = tarfile.TarInfo('ca-chain.crt')
                ca_info.size = len(b'CA CERT CONTENT')
                tar.addfile(ca_info, fileobj=io.BytesIO(b'CA CERT CONTENT'))
                
                # Add server certificate
                server_cert_info = tarfile.TarInfo('server.crt')
                server_cert_info.size = len(b'SERVER CERT CONTENT')
                tar.addfile(server_cert_info, fileobj=io.BytesIO(b'SERVER CERT CONTENT'))
                
                # Add server key
                server_key_info = tarfile.TarInfo('server.key')
                server_key_info.size = len(b'SERVER KEY CONTENT')
                tar.addfile(server_key_info, fileobj=io.BytesIO(b'SERVER KEY CONTENT'))
                
                # Add UDP config
                udp_config_info = tarfile.TarInfo('server-udp.ovpn')
                udp_config_info.size = len(b'UDP CONFIG CONTENT')
                tar.addfile(udp_config_info, fileobj=io.BytesIO(b'UDP CONFIG CONTENT'))
                
                # Add TCP config
                tcp_config_info = tarfile.TarInfo('server-tcp.ovpn')
                tcp_config_info.size = len(b'TCP CONFIG CONTENT')
                tar.addfile(tcp_config_info, fileobj=io.BytesIO(b'TCP CONFIG CONTENT'))
                
                # Add TLS certificate
                tls_cert_info = tarfile.TarInfo('tls-auth.crt')
                tls_cert_info.size = len(b'TLS CERT CONTENT')
                tar.addfile(tls_cert_info, fileobj=io.BytesIO(b'TLS CERT CONTENT'))
            
            # Read the tar content
            with open(temp_tar.name, 'rb') as f:
                tar_content = f.read()
        
        # Extract files
        result = extract_server_files(tar_content, target_dir)
        
        # Verify directory structure was created
        assert result['cert_dir'] == target_dir / 'cert'
        assert result['key_dir'] == target_dir / 'key'
        assert result['udp_dir'] == target_dir / 'udp-1194'
        assert result['tcp_dir'] == target_dir / 'tcp-443'
        
        # Verify files were extracted to correct locations
        assert (target_dir / 'cert' / 'ca-chain.crt').read_bytes() == b'CA CERT CONTENT'
        assert (target_dir / 'cert' / 'server.crt').read_bytes() == b'SERVER CERT CONTENT'
        assert (target_dir / 'key' / 'server.key').read_bytes() == b'SERVER KEY CONTENT'
        assert (target_dir / 'udp-1194' / 'server-udp.ovpn').read_bytes() == b'UDP CONFIG CONTENT'
        assert (target_dir / 'tcp-443' / 'server-tcp.ovpn').read_bytes() == b'TCP CONFIG CONTENT'
        assert (target_dir / 'cert' / 'tls-auth.crt').read_bytes() == b'TLS CERT CONTENT'
    
    def test_extract_server_files_unknown_file_type(self, tmp_path, capsys):
        """Tests handling of unknown file types."""
        target_dir = tmp_path / "openvpn"
        
        # Create a test tar file with an unknown file type
        with tempfile.NamedTemporaryFile() as temp_tar:
            with tarfile.open(temp_tar.name, 'w') as tar:
                # Add unknown file type
                unknown_info = tarfile.TarInfo('unknown.txt')
                unknown_info.size = len(b'UNKNOWN CONTENT')
                tar.addfile(unknown_info, fileobj=io.BytesIO(b'UNKNOWN CONTENT'))
            
            # Read the tar content
            with open(temp_tar.name, 'rb') as f:
                tar_content = f.read()
        
        # Extract files
        extract_server_files(tar_content, target_dir)
        
        # Verify warning was printed
        captured = capsys.readouterr()
        assert "Warning: Unknown file type 'unknown.txt', skipping" in captured.out
    
    def test_extract_server_files_with_directory(self, tmp_path):
        """Tests handling of directory entries in tar file (line 176 coverage)."""
        target_dir = tmp_path / "openvpn"
        
        # Create a test tar file with a directory entry
        with tempfile.NamedTemporaryFile() as temp_tar:
            with tarfile.open(temp_tar.name, 'w') as tar:
                # Add a directory entry
                dir_info = tarfile.TarInfo('some_directory/')
                dir_info.type = tarfile.DIRTYPE
                tar.addfile(dir_info)
                
                # Add a regular file to ensure extraction still works
                ca_info = tarfile.TarInfo('ca.crt')
                ca_info.size = len(b'CA CONTENT')
                tar.addfile(ca_info, fileobj=io.BytesIO(b'CA CONTENT'))
            
            # Read the tar content
            with open(temp_tar.name, 'rb') as f:
                tar_content = f.read()
        
        # Extract files - should skip directory and process file
        result = extract_server_files(tar_content, target_dir)
        
        # Verify the file was extracted (directory was skipped)
        assert (target_dir / 'cert' / 'ca.crt').read_bytes() == b'CA CONTENT'
    
    def test_extract_server_files_unknown_cert_file(self, tmp_path):
        """Tests handling of unknown certificate file types (line 203 coverage)."""
        target_dir = tmp_path / "openvpn"
        
        # Create a test tar file with an unknown certificate file
        with tempfile.NamedTemporaryFile() as temp_tar:
            with tarfile.open(temp_tar.name, 'w') as tar:
                # Add unknown certificate file (not matching any specific patterns)
                unknown_cert_info = tarfile.TarInfo('client.pem')
                unknown_cert_info.size = len(b'UNKNOWN CERT CONTENT')
                tar.addfile(unknown_cert_info, fileobj=io.BytesIO(b'UNKNOWN CERT CONTENT'))
            
            # Read the tar content
            with open(temp_tar.name, 'rb') as f:
                tar_content = f.read()
        
        # Extract files
        extract_server_files(tar_content, target_dir)
        
        # Verify the unknown cert file was placed in cert directory
        assert (target_dir / 'cert' / 'client.pem').read_bytes() == b'UNKNOWN CERT CONTENT'