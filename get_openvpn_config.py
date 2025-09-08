#!/usr/bin/env python3
import os
import click
import requests
import webbrowser
import socket
import yaml
import time
import threading
import tarfile
import tempfile
from pathlib import Path
from platformdirs import user_downloads_path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# A simple list to act as a message queue between threads.
_RECEIVED_TOKEN = []

# --- Configuration Logic (from config.py) ---

class Config:
    """
    Resolves client configuration from multiple sources in a defined order
    of precedence: CLI > Environment > User Config > System Config > Default.
    """
    def __init__(self, server_url=None, output=None, overwrite=None, options=None, _user_config_path=None, _system_config_path=None):
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.yaml")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.yaml")
        
        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        self.server_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')
        self.output_path = self._resolve_output_path(output)
        self.overwrite = self._resolve_overwrite_flag(overwrite)
        self.options = self._resolve(options, 'OVPN_MANAGER_OPTIONS', 'options')

    def _load_config_file(self, path: Path):
        """Safely loads and parses a YAML file."""
        if path.is_file():
            try:
                with path.open('r') as f:
                    return yaml.safe_load(f) or {}
            except (yaml.YAMLError, IOError):
                pass
        return {}

    def _resolve(self, cli_arg, env_var, config_key):
        """Generic resolver that checks CLI > ENV > User > System."""
        if cli_arg is not None:
            return cli_arg
        if os.getenv(env_var):
            return os.getenv(env_var)
        if config_key in self.user_config:
            return self.user_config[config_key]
        if config_key in self.system_config:
            return self.system_config[config_key]
        return None

    def _resolve_output_path(self, cli_arg):
        path_str = self._resolve(cli_arg, 'OVPN_MANAGER_OUTPUT', 'output')
        if path_str:
            return Path(os.path.expanduser(path_str))
        try:
            downloads_dir = user_downloads_path()
            return downloads_dir / "config.ovpn"
        except Exception:
            return Path.home() / "config.ovpn"
                
    def _resolve_overwrite_flag(self, cli_arg):
        if cli_arg:
            return True
        overwrite_str = self._resolve(None, 'OVPN_MANAGER_OVERWRITE', 'overwrite')
        if overwrite_str is not None:
            return str(overwrite_str).lower() in ['true', '1', 't', 'y', 'yes']
        return False

# --- API Client Logic (from api_client.py) ---

class _CallbackHandler(BaseHTTPRequestHandler):
    """A simple server to handle the OIDC callback and capture the token."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
            <html><body onload="window.close()">
            <h1>Authentication successful!</h1><p>You can close this tab.</p>
            <script>window.close();</script></body></html>
        """)

        query_components = parse_qs(urlparse(self.path).query)
        if 'token' in query_components:
            token = query_components["token"][0]
            _RECEIVED_TOKEN.append(token)

    def log_message(self, format, *args):
        return

def _find_free_port():
    """Finds and returns an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def get_profile_with_oidc(config, output_auth_url=None):
    """Handles the full OIDC browser-based authentication flow."""
    port = _find_free_port()
    httpd = HTTPServer(('127.0.0.1', port), _CallbackHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    login_url = f"{config.server_url}/auth/login?cli_port={port}&optionset={config.options}"
    
    if output_auth_url:
        # Instead of opening browser, output URL to specified file/stderr
        if output_auth_url == 'stderr':
            click.echo(f"AUTH_URL: {login_url}", err=True)
        else:
            with open(output_auth_url, 'w') as f:
                f.write(login_url)
    else:
        webbrowser.open(login_url)

    timeout = time.time() + 120
    while not _RECEIVED_TOKEN:
        time.sleep(1)
        if time.time() > timeout:
            httpd.shutdown()
            raise click.ClickException("Authentication timed out.")

    httpd.shutdown()
    token = _RECEIVED_TOKEN.pop(0)

    download_url = f"{config.server_url}/download?token={token}"
    response = requests.get(download_url, timeout=30)
    response.raise_for_status()
    return response.content

def get_profile_with_psk(config, psk):
    """Handles PSK-based authentication for server bundle retrieval."""
    url = f"{config.server_url}/api/v1/server/bundle"
    headers = {'Authorization': f'Bearer {psk}'}

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.content

def extract_server_files(tar_content, target_dir):
    """
    Extracts tar file contents and places files in appropriate directories.
    
    Expected file structure:
    - CA certificate chain -> /cert/
    - Server certificate -> /cert/
    - Server key -> /key/
    - UDP/1194 config -> /udp-1194/
    - TCP/443 config -> /tcp-443/
    - TLS cert (optional) -> /cert/
    """
    target_path = Path(target_dir)
    
    # Create target directories
    cert_dir = target_path / "cert"
    key_dir = target_path / "key"
    udp_dir = target_path / "udp-1194"
    tcp_dir = target_path / "tcp-443"
    
    cert_dir.mkdir(parents=True, exist_ok=True)
    key_dir.mkdir(parents=True, exist_ok=True)
    udp_dir.mkdir(parents=True, exist_ok=True)
    tcp_dir.mkdir(parents=True, exist_ok=True)
    
    with tempfile.NamedTemporaryFile() as temp_tar:
        temp_tar.write(tar_content)
        temp_tar.flush()
        
        with tarfile.open(temp_tar.name, 'r') as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                    
                filename = Path(member.name).name
                file_content = tar.extractfile(member).read()
                
                # Determine destination based on file type
                if filename.endswith(('.crt', '.pem')) and 'ca' in filename.lower():
                    # CA certificate chain
                    dest_path = cert_dir / filename
                elif filename.endswith(('.crt', '.pem')) and 'server' in filename.lower():
                    # Server certificate
                    dest_path = cert_dir / filename
                elif filename.endswith('.key') and 'server' in filename.lower():
                    # Server key
                    dest_path = key_dir / filename
                elif filename.endswith('.ovpn') and 'udp' in filename.lower():
                    # UDP configuration
                    dest_path = udp_dir / filename
                elif filename.endswith('.ovpn') and 'tcp' in filename.lower():
                    # TCP configuration
                    dest_path = tcp_dir / filename
                elif filename.endswith(('.crt', '.pem')) and 'tls' in filename.lower():
                    # TLS certificate (optional)
                    dest_path = cert_dir / filename
                else:
                    # Default to cert directory for unknown certificate files
                    if filename.endswith(('.crt', '.pem')):
                        dest_path = cert_dir / filename
                    else:
                        click.echo(f"Warning: Unknown file type '{filename}', skipping")
                        continue
                
                # Write file to destination
                with open(dest_path, 'wb') as f:
                    f.write(file_content)
                
                click.echo(f"Extracted {filename} -> {dest_path}")
    
    return {
        'cert_dir': cert_dir,
        'key_dir': key_dir,
        'udp_dir': udp_dir,
        'tcp_dir': tcp_dir
    }

# --- CLI Logic (from cli.py) ---

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """A command-line tool to retrieve OpenVPN profiles."""
    pass # pragma: no cover

@cli.command()
@click.option('-s', '--server-url', help='The base URL of the configuration server.')
@click.option('-o', '--output', help='Path to save the OVPN configuration file.')
@click.option('-f', '--force', is_flag=True, help='Overwrite the output file if it already exists.')
@click.option('--options', help='A comma-separated list of OVPN options to enable.')
@click.option('--output-auth-url', help='Output authentication URL to file/stderr instead of opening browser (for testing).')
def get_oidc_profile(server_url, output, force, options, output_auth_url):
    """Fetches a profile using the browser-based OIDC login flow."""
    try:
        config = Config(server_url, output, force, options)

        if not config.server_url:
            raise click.ClickException("Server URL is not configured.")

        if config.output_path.exists() and not config.overwrite:
            raise click.ClickException(f"Output file '{config.output_path}' already exists. Use --force to overwrite.")

        click.echo("Starting OIDC login flow...")
        profile_content = get_profile_with_oidc(config, output_auth_url)
        
        with open(config.output_path, 'wb') as f:
            f.write(profile_content)
        click.secho(f"Successfully saved configuration to {config.output_path}", fg="green")

    except Exception as e:
        raise click.ClickException(f"An error occurred: {e}")

@cli.command()
@click.option('-s', '--server-url', help='The base URL of the configuration server.')
@click.option('--target-dir', default='/etc/openvpn', help='Target directory for OpenVPN files (default: /etc/openvpn).')
@click.option('-f', '--force', is_flag=True, help='Overwrite existing files.')
@click.option('--psk', required=True, envvar='OVPN_PSK', help='The pre-shared key for the device.')
def get_psk_profile(server_url, target_dir, force, psk):
    """Fetches a server profile using a Pre-Shared Key and extracts files to target directory."""
    try:
        config = Config(server_url)

        if not config.server_url:
            raise click.ClickException("Server URL is not configured.")

        target_path = Path(target_dir)
        
        # Check if target directory exists and has content (unless force is used)
        if not force and target_path.exists():
            existing_files = list(target_path.rglob('*'))
            if existing_files:
                raise click.ClickException(f"Target directory '{target_path}' contains files. Use --force to overwrite.")
        
        click.echo(f"Requesting server profile...")
        tar_content = get_profile_with_psk(config, psk)
        
        click.echo(f"Extracting files to {target_path}...")
        dirs = extract_server_files(tar_content, target_path)
        
        click.secho("Successfully extracted server configuration files:", fg="green")
        click.echo(f"  - Certificates: {dirs['cert_dir']}")
        click.echo(f"  - Private keys: {dirs['key_dir']}")
        click.echo(f"  - UDP config: {dirs['udp_dir']}")
        click.echo(f"  - TCP config: {dirs['tcp_dir']}")

    except Exception as e:
        raise click.ClickException(f"An error occurred: {e}")

if __name__ == '__main__':
    cli() # pragma: no cover