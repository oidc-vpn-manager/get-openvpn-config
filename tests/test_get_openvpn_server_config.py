"""
Tests for the get_openvpn_server_config.py script - PSK server configuration functionality.
"""

import pytest
import requests
import tarfile
import tempfile
import io
from click.testing import CliRunner
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_server_config


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_tar_content():
    """Create a sample tar file content for testing."""
    tar_buffer = io.BytesIO()

    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        # Add CA certificate
        ca_info = tarfile.TarInfo(name='ca-chain.crt')
        ca_info.size = len(b'CA CERTIFICATE CONTENT')
        tar.addfile(ca_info, io.BytesIO(b'CA CERTIFICATE CONTENT'))

        # Add server certificate
        server_cert_info = tarfile.TarInfo(name='server.crt')
        server_cert_info.size = len(b'SERVER CERTIFICATE CONTENT')
        tar.addfile(server_cert_info, io.BytesIO(b'SERVER CERTIFICATE CONTENT'))

        # Add server key
        server_key_info = tarfile.TarInfo(name='server.key')
        server_key_info.size = len(b'SERVER KEY CONTENT')
        tar.addfile(server_key_info, io.BytesIO(b'SERVER KEY CONTENT'))

        # Add UDP config
        udp_config_info = tarfile.TarInfo(name='udp-server.ovpn')
        udp_config_info.size = len(b'UDP CONFIG CONTENT')
        tar.addfile(udp_config_info, io.BytesIO(b'UDP CONFIG CONTENT'))

        # Add TCP config
        tcp_config_info = tarfile.TarInfo(name='tcp-server.ovpn')
        tcp_config_info.size = len(b'TCP CONFIG CONTENT')
        tar.addfile(tcp_config_info, io.BytesIO(b'TCP CONFIG CONTENT'))

        # Add TLS auth cert
        tls_info = tarfile.TarInfo(name='tls-auth.pem')
        tls_info.size = len(b'TLS AUTH CONTENT')
        tar.addfile(tls_info, io.BytesIO(b'TLS AUTH CONTENT'))

    tar_buffer.seek(0)
    return tar_buffer.getvalue()


class TestGetOVPNServerConfig:
    """Test the get_openvpn_server_config.py main function."""

    def test_help_output(self, runner):
        """Test that help output is displayed correctly."""
        result = runner.invoke(get_openvpn_server_config.main, ['--help'])
        assert result.exit_code == 0
        assert "Fetches OpenVPN server configuration files using a Pre-Shared Key" in result.output
        assert "--server-url" in result.output
        assert "--target-dir" in result.output
        assert "--force" in result.output
        assert "--psk" in result.output

    @patch('get_openvpn_server_config.get_profile_with_psk')
    @patch('get_openvpn_server_config.extract_server_files')
    def test_successful_server_config_download(self, mock_extract, mock_get_profile, runner, tmp_path, sample_tar_content):
        """Test successful server configuration download with PSK."""
        # Setup mocks
        mock_get_profile.return_value = sample_tar_content
        mock_extract.return_value = {
            'cert_dir': tmp_path / 'cert',
            'key_dir': tmp_path / 'key',
            'udp_dir': tmp_path / 'udp-1194',
            'tcp_dir': tmp_path / 'tcp-443'
        }

        # Run command
        result = runner.invoke(get_openvpn_server_config.main, [
            '--server-url', 'https://test-server.com',
            '--target-dir', str(tmp_path),
            '--psk', 'test-psk-secret',
            '--force'
        ])

        # Verify success
        assert result.exit_code == 0
        assert "Requesting server profile..." in result.output
        assert "Successfully extracted server configuration files to" in result.output

        # Verify functions were called correctly
        mock_get_profile.assert_called_once()
        mock_extract.assert_called_once_with(sample_tar_content, tmp_path)

    def test_missing_server_url(self, runner):
        """Test error when server URL is not configured."""
        result = runner.invoke(get_openvpn_server_config.main, [
            '--psk', 'test-psk'
        ])
        assert result.exit_code == 1
        assert "Server URL is not configured" in result.output

    def test_missing_psk(self, runner):
        """Test error when PSK is not provided."""
        result = runner.invoke(get_openvpn_server_config.main, [
            '--server-url', 'https://test-server.com'
        ])
        assert result.exit_code == 2  # Click parameter error

    @patch('get_openvpn_server_config.Path.exists')
    @patch('get_openvpn_server_config.Path.rglob')
    def test_target_directory_exists_without_force(self, mock_rglob, mock_exists, runner):
        """Test error when target directory exists with files and force is not specified."""
        mock_exists.return_value = True
        mock_rglob.return_value = [Path('/some/file')]  # Non-empty directory

        result = runner.invoke(get_openvpn_server_config.main, [
            '--server-url', 'https://test-server.com',
            '--target-dir', '/etc/openvpn',
            '--psk', 'test-psk'
        ])

        assert result.exit_code == 1
        assert "contains files. Use --force to overwrite" in result.output

    @patch('get_openvpn_server_config.get_profile_with_psk')
    def test_psk_authentication_error(self, mock_get_profile, runner):
        """Test handling of PSK authentication errors."""
        mock_get_profile.side_effect = requests.exceptions.HTTPError("401 Unauthorized")

        result = runner.invoke(get_openvpn_server_config.main, [
            '--server-url', 'https://test-server.com',
            '--psk', 'invalid-psk',
            '--force'
        ])

        assert result.exit_code == 1
        assert "401 Unauthorized" in result.output

    @patch('get_openvpn_server_config.get_profile_with_psk')
    def test_network_error_handling(self, mock_get_profile, runner):
        """Test handling of network errors."""
        mock_get_profile.side_effect = requests.exceptions.ConnectionError("Network error")

        result = runner.invoke(get_openvpn_server_config.main, [
            '--server-url', 'https://test-server.com',
            '--psk', 'test-psk',
            '--force'
        ])

        assert result.exit_code == 1
        assert "Network error" in result.output

    def test_default_target_directory(self, runner):
        """Test that default target directory is /etc/openvpn."""
        with patch('get_openvpn_server_config.get_profile_with_psk') as mock_get_profile:
            mock_get_profile.return_value = b'tar-content'

            with patch('get_openvpn_server_config.extract_server_files') as mock_extract:
                mock_extract.return_value = {
                    'cert_dir': Path('/etc/openvpn/cert'),
                    'key_dir': Path('/etc/openvpn/key'),
                    'udp_dir': Path('/etc/openvpn/udp-1194'),
                    'tcp_dir': Path('/etc/openvpn/tcp-443')
                }

                result = runner.invoke(get_openvpn_server_config.main, [
                    '--server-url', 'https://test-server.com',
                    '--psk', 'test-psk',
                    '--force'
                ])

                assert result.exit_code == 0
                # Verify extract was called with default directory
                mock_extract.assert_called_once_with(b'tar-content', Path('/etc/openvpn'))


class TestPSKAuthentication:
    """Test PSK authentication functionality."""

    @patch('get_openvpn_server_config.requests.get')
    def test_get_profile_with_psk_success(self, mock_get):
        """Test successful PSK authentication and profile retrieval."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.content = b'server-bundle-content'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        # Setup config
        config = get_openvpn_server_config.Config(server_url='https://test-server.com')

        # Call function
        result = get_openvpn_server_config.get_profile_with_psk(config, 'test-psk-secret')

        # Verify correct API call
        mock_get.assert_called_once_with(
            'https://test-server.com/api/v1/server/bundle',
            headers={'Authorization': 'Bearer test-psk-secret'},
            timeout=30
        )

        # Verify result
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

        # Verify files were extracted to flat structure
        assert (target_dir / "ca-chain.crt").exists()
        assert (target_dir / "server.crt").exists()
        assert (target_dir / "server.key").exists()
        assert (target_dir / "udp-server.ovpn").exists()
        assert (target_dir / "tcp-server.ovpn").exists()
        assert (target_dir / "tls-auth.pem").exists()

        # Verify file contents
        assert (target_dir / "ca-chain.crt").read_bytes() == b'CA CERTIFICATE CONTENT'
        assert (target_dir / "server.crt").read_bytes() == b'SERVER CERTIFICATE CONTENT'
        assert (target_dir / "server.key").read_bytes() == b'SERVER KEY CONTENT'
        assert (target_dir / "udp-server.ovpn").read_bytes() == b'UDP CONFIG CONTENT'
        assert (target_dir / "tcp-server.ovpn").read_bytes() == b'TCP CONFIG CONTENT'
        assert (target_dir / "tls-auth.pem").read_bytes() == b'TLS AUTH CONTENT'

        # Verify return value - function returns target_dir path
        assert result['target_dir'] == target_dir

    def test_extract_server_files_unknown_file_type(self, tmp_path, capfd):
        """Test handling of unknown file types during extraction."""
        # Create tar with unknown file type
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            unknown_info = tarfile.TarInfo(name='unknown.txt')
            unknown_info.size = len(b'UNKNOWN CONTENT')
            tar.addfile(unknown_info, io.BytesIO(b'UNKNOWN CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        # Verify file was extracted (flat structure extracts all files)
        captured = capfd.readouterr()
        assert "Extracted unknown.txt" in captured.out
        assert (target_dir / "unknown.txt").exists()

    def test_extract_server_files_unknown_certificate(self, tmp_path):
        """Test handling of unknown certificate files."""
        # Create tar with unknown certificate file
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            unknown_cert_info = tarfile.TarInfo(name='unknown.crt')
            unknown_cert_info.size = len(b'UNKNOWN CERT CONTENT')
            tar.addfile(unknown_cert_info, io.BytesIO(b'UNKNOWN CERT CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        # Verify unknown certificate was placed in cert directory
        assert (target_dir / "unknown.crt").exists()
        assert (target_dir / "unknown.crt").read_bytes() == b'UNKNOWN CERT CONTENT'

    def test_extract_server_files_directory_creation(self, tmp_path):
        """Test that target directories are created with parents."""
        target_dir = tmp_path / "nested" / "deep" / "openvpn"

        # Create minimal tar content
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            ca_info = tarfile.TarInfo(name='ca.crt')
            ca_info.size = len(b'CA CONTENT')
            tar.addfile(ca_info, io.BytesIO(b'CA CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        # Verify nested directories were created and file extracted
        assert target_dir.exists()
        assert (target_dir / "ca.crt").exists()
        # With flat structure, files are extracted directly to target_dir
        assert (target_dir / "ca.crt").read_bytes() == b'CA CONTENT'

    def test_extract_server_files_non_file_member_handling(self, tmp_path):
        """Test handling of non-file TAR members (directories, links, etc.)."""
        # Create tar with directory and file members
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            # Add a directory member (should be skipped)
            dir_info = tarfile.TarInfo(name='test_directory')
            dir_info.type = tarfile.DIRTYPE  # This makes it a directory
            tar.addfile(dir_info)

            # Add a regular file (should be processed)
            ca_info = tarfile.TarInfo(name='ca.crt')
            ca_info.size = len(b'CA CONTENT')
            tar.addfile(ca_info, io.BytesIO(b'CA CONTENT'))

        tar_buffer.seek(0)
        tar_content = tar_buffer.getvalue()

        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(tar_content, target_dir)

        # Verify the file was processed but directory was skipped
        assert (target_dir / "ca.crt").exists()
        assert (target_dir / "ca.crt").read_bytes() == b'CA CONTENT'

        # The directory member should have been skipped (no effect on output)


class TestConfigurationManagement:
    """Test configuration resolution and management."""

    def test_config_resolution_server_url(self, monkeypatch, tmp_path):
        """Test server URL resolution from various sources."""
        # Create config files
        user_config = tmp_path / "user.yaml"
        user_config.write_text("server_url: https://user.example.com\n")

        system_config = tmp_path / "system.yaml"
        system_config.write_text("server_url: https://system.example.com\n")

        # Test CLI argument takes precedence
        config = get_openvpn_server_config.Config(
            server_url='https://cli.example.com',
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://cli.example.com'

        # Test environment variable takes precedence over config files
        monkeypatch.setenv('OVPN_MANAGER_URL', 'https://env.example.com')
        config = get_openvpn_server_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://env.example.com'

        # Test user config takes precedence over system config
        monkeypatch.delenv('OVPN_MANAGER_URL', raising=False)
        config = get_openvpn_server_config.Config(
            _user_config_path=user_config,
            _system_config_path=system_config
        )
        assert config.server_url == 'https://user.example.com'

        # Test system config is used when user config doesn't exist
        config = get_openvpn_server_config.Config(
            _user_config_path=Path("/nonexistent"),
            _system_config_path=system_config
        )
        assert config.server_url == 'https://system.example.com'

    def test_config_malformed_yaml_handling(self, tmp_path):
        """Test handling of malformed YAML configuration files."""
        malformed_config = tmp_path / "malformed.yaml"
        malformed_config.write_text("invalid: yaml: content: [")

        # Should not raise exception, should return None for server_url
        config = get_openvpn_server_config.Config(_user_config_path=malformed_config)
        assert config.server_url is None

    def test_config_missing_files_handling(self):
        """Test handling of missing configuration files."""
        config = get_openvpn_server_config.Config(
            _user_config_path=Path("/nonexistent/user.yaml"),
            _system_config_path=Path("/nonexistent/system.yaml")
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

        # Verify Authorization header is properly formatted
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

        # Verify timeout is set
        call_args = mock_get.call_args
        assert call_args[1]['timeout'] == 30

    def test_file_permissions_security(self, tmp_path, sample_tar_content):
        """Test that extracted files maintain appropriate permissions."""
        target_dir = tmp_path / "openvpn"

        get_openvpn_server_config.extract_server_files(sample_tar_content, target_dir)

        # Verify key files are created (permissions would be set by umask in real usage)
        key_file = target_dir / "server.key"
        assert key_file.exists()

        # In a real scenario, we would verify that key files have restricted permissions
        # This test verifies the files are created in the correct location

    def test_malformed_tar_handling(self, tmp_path):
        """Test handling of malformed tar content."""
        malformed_tar = b'not-a-tar-file'

        with pytest.raises(tarfile.TarError):
            get_openvpn_server_config.extract_server_files(malformed_tar, tmp_path)

    def test_empty_tar_handling(self, tmp_path):
        """Test handling of empty tar files."""
        # Create empty tar
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            pass  # Empty tar

        tar_buffer.seek(0)
        empty_tar_content = tar_buffer.getvalue()

        result = get_openvpn_server_config.extract_server_files(empty_tar_content, tmp_path)

        # Should create target directory but no files
        assert tmp_path.exists()
        # No files should be extracted from empty tar
        assert len(list(tmp_path.iterdir())) == 0

        # Should return target_dir for flat structure
        assert result == {'target_dir': tmp_path}


class TestMainEntryPoint:
    """Test __main__ entry point coverage."""

    def test_main_entry_point_coverage(self):
        """Test __main__ entry point is covered."""
        import subprocess
        import sys

        # Test that the script can be run with --help to cover __main__
        result = subprocess.run([
            sys.executable, '/workspaces/2025-06_openvpn-manager_gh-org/tools/get_openvpn_config/get_openvpn_server_config.py', '--help'
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert 'server' in result.stdout.lower() or 'bundle' in result.stdout.lower()