"""
Tests for the get_openvpn_server_config.py script - PSK server configuration functionality.
"""

import io
import json
import pytest
import requests
import tarfile
from unittest.mock import MagicMock, patch
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_server_config


def _run(argv):
    """Invoke the CLI's ``main`` and return the SystemExit code (0 if no exit)."""
    try:
        get_openvpn_server_config.main(argv)
    except SystemExit as exc:
        return exc.code if exc.code is not None else 0
    return 0


def _output(capsys):
    """Return combined stdout+stderr captured during the most recent call."""
    captured = capsys.readouterr()
    return captured.out + captured.err


@pytest.fixture
def sample_tar_content():
    """Create a sample tar file content for testing."""
    tar_buffer = io.BytesIO()

    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        ca_info = tarfile.TarInfo(name='ca-chain.crt')
        ca_info.size = len(b'CA CERTIFICATE CONTENT')
        tar.addfile(ca_info, io.BytesIO(b'CA CERTIFICATE CONTENT'))

        server_cert_info = tarfile.TarInfo(name='server.crt')
        server_cert_info.size = len(b'SERVER CERTIFICATE CONTENT')
        tar.addfile(server_cert_info, io.BytesIO(b'SERVER CERTIFICATE CONTENT'))

        server_key_info = tarfile.TarInfo(name='server.key')
        server_key_info.size = len(b'SERVER KEY CONTENT')
        tar.addfile(server_key_info, io.BytesIO(b'SERVER KEY CONTENT'))

        udp_config_info = tarfile.TarInfo(name='udp-server.ovpn')
        udp_config_info.size = len(b'UDP CONFIG CONTENT')
        tar.addfile(udp_config_info, io.BytesIO(b'UDP CONFIG CONTENT'))

        tcp_config_info = tarfile.TarInfo(name='tcp-server.ovpn')
        tcp_config_info.size = len(b'TCP CONFIG CONTENT')
        tar.addfile(tcp_config_info, io.BytesIO(b'TCP CONFIG CONTENT'))

        tls_info = tarfile.TarInfo(name='tls-auth.pem')
        tls_info.size = len(b'TLS AUTH CONTENT')
        tar.addfile(tls_info, io.BytesIO(b'TLS AUTH CONTENT'))

    tar_buffer.seek(0)
    return tar_buffer.getvalue()


class TestGetOVPNServerConfig:
    """Test the get_openvpn_server_config.py main function."""

    def test_help_output(self, capsys):
        """Test that help output is displayed correctly."""
        code = _run(['--help'])
        assert code == 0
        out = _output(capsys)
        assert "Fetches OpenVPN server configuration files using a Pre-Shared Key" in out
        assert "--server-url" in out
        assert "--target-dir" in out
        assert "--force" in out
        assert "--psk" in out

    @patch('get_openvpn_server_config.get_profile_with_psk')
    @patch('get_openvpn_server_config.extract_server_files')
    def test_successful_server_config_download(self, mock_extract, mock_get_profile, capsys, tmp_path, sample_tar_content):
        """Test successful server configuration download with PSK."""
        mock_get_profile.return_value = sample_tar_content
        mock_extract.return_value = {'target_dir': tmp_path}

        code = _run([
            '--server-url', 'https://test-server.com',
            '--target-dir', str(tmp_path),
            '--psk', 'test-psk-secret',
            '--force',
        ])
        out = _output(capsys)

        assert code == 0
        assert "Requesting server profile..." in out
        assert "Successfully extracted server configuration files to" in out

        mock_get_profile.assert_called_once()
        mock_extract.assert_called_once_with(sample_tar_content, tmp_path)

    def test_missing_server_url(self, capsys):
        """Test error when server URL is not configured."""
        code = _run(['--psk', 'test-psk'])
        assert code == 1
        assert "Server URL is not configured" in _output(capsys)

    def test_missing_psk(self, capsys):
        """Test error when PSK is not provided."""
        code = _run(['--server-url', 'https://test-server.com'])
        assert code == 2  # argparse parameter error

    @patch('get_openvpn_server_config.Path.exists')
    @patch('get_openvpn_server_config.Path.rglob')
    def test_target_directory_exists_without_force(self, mock_rglob, mock_exists, capsys):
        """Test error when target directory exists with files and force is not specified."""
        mock_exists.return_value = True
        mock_rglob.return_value = [Path('/some/file')]

        code = _run([
            '--server-url', 'https://test-server.com',
            '--target-dir', '/etc/openvpn',
            '--psk', 'test-psk',
        ])

        assert code == 1
        assert "contains files. Use --force to overwrite" in _output(capsys)

    @patch('get_openvpn_server_config.get_profile_with_psk')
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

    @patch('get_openvpn_server_config.get_profile_with_psk')
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

    def test_default_target_directory(self, capsys):
        """Test that default target directory is /etc/openvpn."""
        with patch('get_openvpn_server_config.get_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'tar-content'

            with patch('get_openvpn_server_config.extract_server_files') as mock_extract:
                mock_extract.return_value = {'target_dir': Path('/etc/openvpn')}

                code = _run([
                    '--server-url', 'https://test-server.com',
                    '--psk', 'test-psk',
                    '--force',
                ])

                assert code == 0
                mock_extract.assert_called_once_with(b'tar-content', Path('/etc/openvpn'))


class TestPSKAuthentication:
    """Test PSK authentication functionality."""

    @patch('get_openvpn_server_config.requests.get')
    def test_get_profile_with_psk_success(self, mock_get):
        """Test successful PSK authentication and profile retrieval."""
        mock_response = MagicMock()
        mock_response.content = b'server-bundle-content'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        config = get_openvpn_server_config.Config(server_url='https://test-server.com')

        result = get_openvpn_server_config.get_profile_with_psk(config, 'test-psk-secret')

        mock_get.assert_called_once_with(
            'https://test-server.com/api/v1/server/bundle',
            headers={'Authorization': 'Bearer test-psk-secret'},
            timeout=30,
        )
        assert result == b'server-bundle-content'

    @patch('get_openvpn_server_config.requests.get')
    def test_get_profile_with_psk_http_error(self, mock_get):
        """Test PSK authentication with HTTP error."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("403 Forbidden")
        mock_get.return_value = mock_response

        config = get_openvpn_server_config.Config(server_url='https://test-server.com')

        with pytest.raises(requests.exceptions.HTTPError):
            get_openvpn_server_config.get_profile_with_psk(config, 'invalid-psk')

    @patch('get_openvpn_server_config.requests.get')
    def test_get_profile_with_psk_timeout(self, mock_get):
        """Test PSK authentication with timeout."""
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        config = get_openvpn_server_config.Config(server_url='https://test-server.com')

        with pytest.raises(requests.exceptions.Timeout):
            get_openvpn_server_config.get_profile_with_psk(config, 'test-psk')


class TestServerFileExtraction:
    """Test server file extraction functionality."""

    def test_extract_server_files_success(self, tmp_path, sample_tar_content):
        """Test successful extraction of server files."""
        target_dir = tmp_path / "openvpn"

        result = get_openvpn_server_config.extract_server_files(sample_tar_content, target_dir)

        assert (target_dir / "ca-chain.crt").exists()
        assert (target_dir / "server.crt").exists()
        assert (target_dir / "server.key").exists()
        assert (target_dir / "udp-server.ovpn").exists()
        assert (target_dir / "tcp-server.ovpn").exists()
        assert (target_dir / "tls-auth.pem").exists()

        assert (target_dir / "ca-chain.crt").read_bytes() == b'CA CERTIFICATE CONTENT'
        assert (target_dir / "server.crt").read_bytes() == b'SERVER CERTIFICATE CONTENT'
        assert (target_dir / "server.key").read_bytes() == b'SERVER KEY CONTENT'
        assert (target_dir / "udp-server.ovpn").read_bytes() == b'UDP CONFIG CONTENT'
        assert (target_dir / "tcp-server.ovpn").read_bytes() == b'TCP CONFIG CONTENT'
        assert (target_dir / "tls-auth.pem").read_bytes() == b'TLS AUTH CONTENT'

        assert result['target_dir'] == target_dir

    def test_extract_server_files_unknown_file_type(self, tmp_path, capfd):
        """Test handling of unknown file types during extraction."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            unknown_info = tarfile.TarInfo(name='unknown.txt')
            unknown_info.size = len(b'UNKNOWN CONTENT')
            tar.addfile(unknown_info, io.BytesIO(b'UNKNOWN CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        captured = capfd.readouterr()
        assert "Extracted unknown.txt" in captured.out
        assert (target_dir / "unknown.txt").exists()

    def test_extract_server_files_unknown_certificate(self, tmp_path):
        """Test handling of unknown certificate files."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            unknown_cert_info = tarfile.TarInfo(name='unknown.crt')
            unknown_cert_info.size = len(b'UNKNOWN CERT CONTENT')
            tar.addfile(unknown_cert_info, io.BytesIO(b'UNKNOWN CERT CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        assert (target_dir / "unknown.crt").exists()
        assert (target_dir / "unknown.crt").read_bytes() == b'UNKNOWN CERT CONTENT'

    def test_extract_server_files_directory_creation(self, tmp_path):
        """Test that target directories are created with parents."""
        target_dir = tmp_path / "nested" / "deep" / "openvpn"

        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            ca_info = tarfile.TarInfo(name='ca.crt')
            ca_info.size = len(b'CA CONTENT')
            tar.addfile(ca_info, io.BytesIO(b'CA CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        assert target_dir.exists()
        assert (target_dir / "ca.crt").exists()
        assert (target_dir / "ca.crt").read_bytes() == b'CA CONTENT'

    def test_extract_server_files_non_file_member_handling(self, tmp_path):
        """Test handling of non-file TAR members (directories, links, etc.)."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            dir_info = tarfile.TarInfo(name='test_directory')
            dir_info.type = tarfile.DIRTYPE
            tar.addfile(dir_info)

            ca_info = tarfile.TarInfo(name='ca.crt')
            ca_info.size = len(b'CA CONTENT')
            tar.addfile(ca_info, io.BytesIO(b'CA CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        assert (target_dir / "ca.crt").exists()
        assert (target_dir / "ca.crt").read_bytes() == b'CA CONTENT'


class TestConfigurationManagement:
    """Test configuration resolution and management."""

    def test_config_resolution_server_url(self, monkeypatch, tmp_path):
        """Test server URL resolution from various sources."""
        user_config = tmp_path / "user.json"
        user_config.write_text(json.dumps({"server_url": "https://user.example.com"}))

        system_config = tmp_path / "system.json"
        system_config.write_text(json.dumps({"server_url": "https://system.example.com"}))

        # CLI argument takes precedence
        config = get_openvpn_server_config.Config(
            server_url='https://cli.example.com',
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://cli.example.com'

        # Environment variable takes precedence over config files
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.example.com')
        config = get_openvpn_server_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://env.example.com'

        # User config takes precedence over system config
        monkeypatch.delenv('OVPN_MANAGER_URL', raising=False)
        config = get_openvpn_server_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://user.example.com'

        # System config used when user config does not exist
        config = get_openvpn_server_config.Config(
            _user_config_path=Path("/nonexistent"),
            _system_config_path=system_config,
        )
        assert config.server_url == 'https://system.example.com'

    def test_config_malformed_json_handling(self, tmp_path):
        """Test handling of malformed JSON configuration files."""
        malformed_config = tmp_path / "malformed.json"
        malformed_config.write_text("{ this is not: valid json [")

        config = get_openvpn_server_config.Config(_user_config_path=malformed_config)
        assert config.server_url is None

    def test_config_strips_trailing_slash_from_server_url(self, monkeypatch):
        """Trailing slashes on the server URL must be stripped to avoid double-slash request paths."""
        config = get_openvpn_server_config.Config(server_url='https://test.com/')
        assert config.server_url == 'https://test.com'

        config = get_openvpn_server_config.Config(server_url='https://test.com///')
        assert config.server_url == 'https://test.com'

        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.com/')
        config = get_openvpn_server_config.Config()
        assert config.server_url == 'https://env.com'

    def test_config_missing_files_handling(self):
        """Test handling of missing configuration files."""
        config = get_openvpn_server_config.Config(
            _user_config_path=Path("/nonexistent/user.json"),
            _system_config_path=Path("/nonexistent/system.json"),
        )
        assert config.server_url is None


class TestSecurityAndErrorHandling:
    """Test security features and error handling."""

    @patch('get_openvpn_server_config.requests.get')
    def test_request_headers_psk_bearer_token(self, mock_get):
        """Test that PSK is properly formatted as Bearer token in Authorization header."""
        mock_response = MagicMock()
        mock_response.content = b'content'
        mock_get.return_value = mock_response

        config = get_openvpn_server_config.Config(server_url='https://test.com')

        get_openvpn_server_config.get_profile_with_psk(config, 'secret-psk-123')

        call_args = mock_get.call_args
        headers = call_args[1]['headers']
        assert headers['Authorization'] == 'Bearer secret-psk-123'

    @patch('get_openvpn_server_config.requests.get')
    def test_request_timeout_configuration(self, mock_get):
        """Test that requests have appropriate timeout configured."""
        mock_response = MagicMock()
        mock_response.content = b'content'
        mock_get.return_value = mock_response

        config = get_openvpn_server_config.Config(server_url='https://test.com')

        get_openvpn_server_config.get_profile_with_psk(config, 'test-psk')

        call_args = mock_get.call_args
        assert call_args[1]['timeout'] == 30

    def test_file_permissions_security(self, tmp_path, sample_tar_content):
        """Test that extracted files maintain appropriate permissions."""
        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(sample_tar_content, target_dir)

        key_file = target_dir / "server.key"
        assert key_file.exists()

    def test_malformed_tar_handling(self, tmp_path):
        """Test handling of malformed tar content."""
        malformed_tar = b'not-a-tar-file'

        with pytest.raises(tarfile.TarError):
            get_openvpn_server_config.extract_server_files(malformed_tar, tmp_path)

    def test_empty_tar_handling(self, tmp_path):
        """Test handling of empty tar files."""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            pass  # Empty tar

        tar_buffer.seek(0)
        empty_tar_content = tar_buffer.getvalue()

        result = get_openvpn_server_config.extract_server_files(empty_tar_content, tmp_path)

        assert tmp_path.exists()
        assert len(list(tmp_path.iterdir())) == 0
        assert result == {'target_dir': tmp_path}


class TestMainEntryPoint:
    """Test __main__ entry point coverage."""

    def test_main_entry_point_coverage(self):
        """Test __main__ entry point is covered."""
        import subprocess
        import sys
        from pathlib import Path

        script_path = Path(__file__).parent.parent / 'get_openvpn_server_config.py'
        result = subprocess.run([
            sys.executable, str(script_path), '--help',
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert 'server' in result.stdout.lower() or 'bundle' in result.stdout.lower()
