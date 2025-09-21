#!/usr/bin/env python3
import os
import click
import requests
import webbrowser
import socket
import yaml
import time
import threading
from pathlib import Path
from platformdirs import user_downloads_path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# A simple list to act as a message queue between threads.
_RECEIVED_TOKEN = []

# --- Configuration Logic ---

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
        """Resolves output file path with fallback to downloads directory.

        Args:
            cli_arg: Command-line output path argument or None

        Returns:
            Path: Resolved output file path for profile
        """
        path_str = self._resolve(cli_arg, 'OVPN_MANAGER_OUTPUT', 'output')
        if path_str:
            return Path(os.path.expanduser(path_str))
        try:
            downloads_dir = user_downloads_path()
            return downloads_dir / "config.ovpn"
        except Exception:
            return Path.home() / "config.ovpn"

    def _resolve_overwrite_flag(self, cli_arg):
        """Resolves overwrite flag from CLI, environment, or config sources.

        Args:
            cli_arg: Command-line overwrite flag or None

        Returns:
            bool: Whether to overwrite existing files
        """
        if cli_arg is not None:
            return cli_arg
        overwrite_str = self._resolve(None, 'OVPN_MANAGER_OVERWRITE', 'overwrite')
        if overwrite_str is not None:
            return str(overwrite_str).lower() in ['true', '1', 't', 'y', 'yes']
        return False

# --- API Client Logic ---

class _CallbackHandler(BaseHTTPRequestHandler):
    """A simple server to handle the OIDC callback and capture the token."""
    def do_GET(self):
        """Handles OIDC callback GET request and extracts token from query parameters."""
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
        """Suppresses HTTP server logging by overriding default behavior."""
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

# --- CLI Logic ---

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('-s', '--server-url', help='The base URL of the configuration server.')
@click.option('-o', '--output', help='Path to save the OVPN configuration file.')
@click.option('-f', '--force', is_flag=True, help='Overwrite the output file if it already exists.')
@click.option('--options', help='A comma-separated list of OVPN options to enable.')
@click.option('--output-auth-url', help='Output authentication URL to file/stderr instead of opening browser (for testing).')
def main(server_url, output, force, options, output_auth_url):
    """Fetches an OpenVPN user profile using the browser-based OIDC login flow."""
    try:
        config = Config(server_url, output, force, options)

        if not config.server_url:
            raise click.ClickException("Server URL is not configured.")

        if config.output_path.exists() and not config.overwrite:
            raise click.ClickException(f"Output file '{config.output_path}' already exists. Use --force to overwrite.")

        # Test server connectivity before starting OIDC flow
        try:
            click.echo("Testing server connectivity...")
            test_response = requests.get(f"{config.server_url}/health", timeout=5)
            test_response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise click.ClickException(f"Cannot connect to server {config.server_url}: {e}")

        click.echo("Starting OIDC login flow...")
        profile_content = get_profile_with_oidc(config, output_auth_url)

        with open(config.output_path, 'wb') as f:
            f.write(profile_content)
        click.secho(f"Successfully saved configuration to {config.output_path}", fg="green")

    except Exception as e:
        raise click.ClickException(f"An error occurred: {e}")

if __name__ == '__main__':
    main()