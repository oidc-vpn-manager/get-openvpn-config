"""
Tests for the get_openvpn_config script's server bundle functionality.
"""

import io
import json
import tarfile
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import requests
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from get_openvpn_config import *


class TestServerBundleIntegration:
    """Test the updated get_profile_with_psk function and server bundle handling."""

    def test_get_profile_with_psk_calls_server_bundle_endpoint(self):
        """Test that get_profile_with_psk calls the correct server bundle endpoint."""
        with patch('get_openvpn_config.requests.get') as mock_get:
            # Setup mock response
            mock_response = MagicMock()
            mock_response.content = b'test-tar-content'
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response

            # Setup config
            config = Config(server_url='http://test-server')
            
            # Call function
            result = get_profile_with_psk(config, 'test-psk')

            # Verify correct endpoint was called
            mock_get.assert_called_once_with(
                'http://test-server/api/v1/server/bundle',
                headers={'Authorization': 'Bearer test-psk'},
                timeout=30
            )
            
            # Verify result
            assert result == b'test-tar-content'

    def test_get_profile_with_psk_handles_http_errors(self):
        """Test that get_profile_with_psk properly handles HTTP errors."""
        with patch('get_openvpn_config.requests.get') as mock_get:
            # Setup mock to raise HTTP error
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
            mock_get.return_value = mock_response

            # Setup config
            config = Config(server_url='http://test-server')
            
            # Call function and expect exception
            with pytest.raises(requests.HTTPError):
                get_profile_with_psk(config, 'test-psk')

    def test_extract_server_files_with_real_tar_structure(self):
        """Test extract_server_files with a realistic tar file structure."""
        # Create a test tar file in memory
        tar_buffer = io.BytesIO()
        
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add CA certificate
            ca_cert_content = b'-----BEGIN CERTIFICATE-----\ntest-ca-cert\n-----END CERTIFICATE-----'
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_cert_content)
            tar.addfile(ca_info, io.BytesIO(ca_cert_content))
            
            # Add server certificate
            server_cert_content = b'-----BEGIN CERTIFICATE-----\ntest-server-cert\n-----END CERTIFICATE-----'
            server_cert_info = tarfile.TarInfo('server.crt')
            server_cert_info.size = len(server_cert_content)
            tar.addfile(server_cert_info, io.BytesIO(server_cert_content))
            
            # Add server key
            server_key_content = b'-----BEGIN PRIVATE KEY-----\ntest-server-key\n-----END PRIVATE KEY-----'
            server_key_info = tarfile.TarInfo('server.key')
            server_key_info.size = len(server_key_content)
            tar.addfile(server_key_info, io.BytesIO(server_key_content))
            
            # Add TLS-Crypt key
            tls_key_content = b'-----BEGIN OpenVPN Static key V1-----\ntest-tls-key\n-----END OpenVPN Static key V1-----'
            tls_key_info = tarfile.TarInfo('tls-crypt.key')
            tls_key_info.size = len(tls_key_content)
            tar.addfile(tls_key_info, io.BytesIO(tls_key_content))
            
            # Add UDP config
            udp_config_content = b'# OpenVPN UDP Server Config\nproto udp\nport 1194\n'
            udp_config_info = tarfile.TarInfo('server-udp-1194.ovpn')
            udp_config_info.size = len(udp_config_content)
            tar.addfile(udp_config_info, io.BytesIO(udp_config_content))
            
            # Add TCP config
            tcp_config_content = b'# OpenVPN TCP Server Config\nproto tcp\nport 443\n'
            tcp_config_info = tarfile.TarInfo('server-tcp-443.ovpn')
            tcp_config_info.size = len(tcp_config_content)
            tar.addfile(tcp_config_info, io.BytesIO(tcp_config_content))

        tar_content = tar_buffer.getvalue()

        # Extract to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            result = extract_server_files(tar_content, temp_dir)
            
            # Verify directory structure
            assert result['cert_dir'] == Path(temp_dir) / "cert"
            assert result['key_dir'] == Path(temp_dir) / "key"
            assert result['udp_dir'] == Path(temp_dir) / "udp-1194"
            assert result['tcp_dir'] == Path(temp_dir) / "tcp-443"
            
            # Verify files were extracted correctly
            ca_cert_path = result['cert_dir'] / "ca-chain.crt"
            assert ca_cert_path.exists()
            assert b'test-ca-cert' in ca_cert_path.read_bytes()
            
            server_cert_path = result['cert_dir'] / "server.crt"
            assert server_cert_path.exists()
            assert b'test-server-cert' in server_cert_path.read_bytes()
            
            server_key_path = result['key_dir'] / "server.key"
            assert server_key_path.exists()
            assert b'test-server-key' in server_key_path.read_bytes()
            
            udp_config_path = result['udp_dir'] / "server-udp-1194.ovpn"
            assert udp_config_path.exists()
            assert b'proto udp' in udp_config_path.read_bytes()
            
            tcp_config_path = result['tcp_dir'] / "server-tcp-443.ovpn"
            assert tcp_config_path.exists()
            assert b'proto tcp' in tcp_config_path.read_bytes()

    def test_extract_server_files_with_empty_tls_key(self):
        """Test extract_server_files when TLS-Crypt key is empty."""
        # Create a test tar file with empty TLS key
        tar_buffer = io.BytesIO()
        
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Add minimal files
            ca_cert_content = b'test-ca-cert'
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_cert_content)
            tar.addfile(ca_info, io.BytesIO(ca_cert_content))
            
            # Add empty TLS-Crypt key
            tls_key_content = b''  # Empty
            tls_key_info = tarfile.TarInfo('tls-crypt.key')
            tls_key_info.size = len(tls_key_content)
            tar.addfile(tls_key_info, io.BytesIO(tls_key_content))

        tar_content = tar_buffer.getvalue()

        # Extract to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should not raise an error with empty TLS key
            result = extract_server_files(tar_content, temp_dir)
            
            # TLS key file should exist but be empty (since it gets skipped due to unknown type)
            # But CA cert should be extracted
            ca_cert_path = result['cert_dir'] / "ca-chain.crt"
            assert ca_cert_path.exists()

    def test_extract_server_files_handles_missing_files(self):
        """Test extract_server_files gracefully handles missing expected files."""
        # Create a tar file with only some expected files
        tar_buffer = io.BytesIO()
        
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Only add CA cert, missing everything else
            ca_cert_content = b'test-ca-cert'
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_cert_content)
            tar.addfile(ca_info, io.BytesIO(ca_cert_content))

        tar_content = tar_buffer.getvalue()

        # Extract to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should not raise an error
            result = extract_server_files(tar_content, temp_dir)
            
            # Should create all expected directories even if files are missing
            assert result['cert_dir'].exists()
            assert result['key_dir'].exists()
            assert result['udp_dir'].exists()
            assert result['tcp_dir'].exists()
            
            # Only CA cert should be present
            ca_cert_path = result['cert_dir'] / "ca-chain.crt"
            assert ca_cert_path.exists()

    def test_extract_server_files_creates_target_directory(self):
        """Test that extract_server_files creates the target directory if it doesn't exist."""
        # Create minimal tar content
        tar_buffer = io.BytesIO()
        
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            ca_cert_content = b'test-ca-cert'
            ca_info = tarfile.TarInfo('ca-chain.crt')
            ca_info.size = len(ca_cert_content)
            tar.addfile(ca_info, io.BytesIO(ca_cert_content))

        tar_content = tar_buffer.getvalue()

        # Use a non-existent directory path
        with tempfile.TemporaryDirectory() as temp_dir:
            target_dir = Path(temp_dir) / "non-existent" / "nested" / "path"
            
            # Should create the directory structure
            result = extract_server_files(tar_content, str(target_dir))
            
            # Verify directories were created
            assert target_dir.exists()
            assert result['cert_dir'].exists()
            assert result['key_dir'].exists()
            assert result['udp_dir'].exists()
            assert result['tcp_dir'].exists()

    def test_get_profile_with_psk_timeout_handling(self):
        """Test that get_profile_with_psk respects timeout parameter."""
        with patch('get_openvpn_config.requests.get') as mock_get:
            # Setup mock response
            mock_response = MagicMock()
            mock_response.content = b'test-content'
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response

            # Setup config
            config = Config(server_url='http://test-server')
            
            # Call function
            get_profile_with_psk(config, 'test-psk')

            # Verify timeout was passed correctly
            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs['timeout'] == 30

    def test_server_bundle_integration_with_config_class(self):
        """Test that Config class works correctly with server bundle functionality."""
        # Test with various config sources
        config = Config(
            server_url='http://configured-server',
            output='/configured/path',
            overwrite=True,
            options='option1,option2'
        )
        
        assert config.server_url == 'http://configured-server'
        assert config.output_path == Path('/configured/path')
        assert config.overwrite == True
        assert config.options == 'option1,option2'

    def test_extract_server_files_file_classification(self):
        """Test that extract_server_files correctly classifies different file types."""
        # Create tar with various file types
        tar_buffer = io.BytesIO()
        
        with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
            # Different types of certificate files
            files_to_add = [
                ('ca-chain.crt', b'ca-cert-content', 'cert'),
                ('server.crt', b'server-cert-content', 'cert'),
                ('server.key', b'server-key-content', 'key'),
                ('server-udp-1194.ovpn', b'udp-config-content', 'udp-1194'),
                ('server-tcp-443.ovpn', b'tcp-config-content', 'tcp-443'),
                ('tls-auth.pem', b'tls-auth-content', 'cert'),  # Should go to cert dir
                ('unknown-file.txt', b'unknown-content', None),  # Should be skipped
            ]
            
            for filename, content, expected_dir in files_to_add:
                file_info = tarfile.TarInfo(filename)
                file_info.size = len(content)
                tar.addfile(file_info, io.BytesIO(content))

        tar_content = tar_buffer.getvalue()

        # Extract to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            result = extract_server_files(tar_content, temp_dir)
            
            # Verify files went to correct directories
            ca_cert = result['cert_dir'] / 'ca-chain.crt'
            assert ca_cert.exists()
            assert ca_cert.read_bytes() == b'ca-cert-content'
            
            server_cert = result['cert_dir'] / 'server.crt'
            assert server_cert.exists()
            assert server_cert.read_bytes() == b'server-cert-content'
            
            server_key = result['key_dir'] / 'server.key'
            assert server_key.exists()
            assert server_key.read_bytes() == b'server-key-content'
            
            udp_config = result['udp_dir'] / 'server-udp-1194.ovpn'
            assert udp_config.exists()
            assert udp_config.read_bytes() == b'udp-config-content'
            
            tcp_config = result['tcp_dir'] / 'server-tcp-443.ovpn'
            assert tcp_config.exists()
            assert tcp_config.read_bytes() == b'tcp-config-content'
            
            tls_auth = result['cert_dir'] / 'tls-auth.pem'
            assert tls_auth.exists()
            assert tls_auth.read_bytes() == b'tls-auth-content'
            
            # Unknown file should not exist anywhere
            for dir_result in result.values():
                unknown_file = dir_result / 'unknown-file.txt'
                assert not unknown_file.exists()