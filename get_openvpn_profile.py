#!/usr/bin/env python3
"""Fetches an OpenVPN user profile using the browser-based OIDC login flow.

Stdlib-only CLI dependencies (argparse + json). Configuration files are JSON.
"""
import argparse
import json
import os
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests


def _user_downloads_path():
    """Return the user's Downloads directory if it exists, else home dir.

    Avoids a hard runtime dep on the third-party ``platformdirs`` package so the
    script can be run as a single file via curl + python3 without pip-installing
    extras beyond what the rest of the script already needs.
    """
    candidate = Path.home() / "Downloads"
    return candidate if candidate.is_dir() else Path.home()


# A simple list to act as a message queue between threads.
_RECEIVED_TOKEN = []


# --- Configuration Logic ---

class Config:
    """
    Resolves client configuration from multiple sources in a defined order
    of precedence: CLI > Environment > User Config > System Config > Default.
    """
    def __init__(self, server_url=None, output=None, overwrite=None, options=None,
                 _user_config_path=None, _system_config_path=None):
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.json")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.json")

        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        resolved_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')
        self.server_url = resolved_url.rstrip('/') if resolved_url else resolved_url
        self.output_path = self._resolve_output_path(output)
        self.overwrite = self._resolve_overwrite_flag(overwrite)
        self.options = self._resolve(options, 'OVPN_MANAGER_OPTIONS', 'options')

    def _load_config_file(self, path: Path):
        """Safely loads and parses a JSON config file."""
        if path.is_file():
            try:
                with path.open('r') as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, IOError):
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
        """Resolves output file path with fallback to downloads directory."""
        path_str = self._resolve(cli_arg, 'OVPN_MANAGER_OUTPUT', 'output')
        if path_str:
            return Path(os.path.expanduser(path_str))
        try:
            downloads_dir = _user_downloads_path()
            return downloads_dir / "config.ovpn"
        except Exception:
            return Path.home() / "config.ovpn"

    def _resolve_overwrite_flag(self, cli_arg):
        """Resolves overwrite flag from CLI, environment, or config sources."""
        if cli_arg is not None:
            return cli_arg
        overwrite_str = self._resolve(None, 'OVPN_MANAGER_OVERWRITE', 'overwrite')
        if overwrite_str is not None:
            if isinstance(overwrite_str, bool):
                return overwrite_str
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
            print(f"AUTH_URL: {login_url}", file=sys.stderr)
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
            raise RuntimeError("Authentication timed out.")

    httpd.shutdown()
    token = _RECEIVED_TOKEN.pop(0)

    download_url = f"{config.server_url}/download?token={token}"
    response = requests.get(download_url, timeout=30)
    response.raise_for_status()
    return response.content


# --- CLI Logic ---

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="get_openvpn_profile.py",
        description="Fetches an OpenVPN user profile using the browser-based OIDC login flow.",
    )
    parser.add_argument('-s', '--server-url', help='The base URL of the configuration server.')
    parser.add_argument('-o', '--output', help='Path to save the OVPN configuration file.')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite the output file if it already exists.')
    parser.add_argument('--options', help='A comma-separated list of OVPN options to enable.')
    parser.add_argument('--output-auth-url',
                        help='Output authentication URL to file/stderr instead of opening browser (for testing).')
    return parser


def main(argv=None):
    """Entry point. Accepts optional argv list to support direct calls from tests."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = Config(args.server_url, args.output, args.force or None, args.options)

        if not config.server_url:
            raise RuntimeError("Server URL is not configured.")

        if config.output_path.exists() and not config.overwrite:
            raise RuntimeError(f"Output file '{config.output_path}' already exists. Use --force to overwrite.")

        # Test server connectivity before starting OIDC flow
        try:
            print("Testing server connectivity...")
            test_response = requests.get(f"{config.server_url}/health", timeout=5)
            test_response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Cannot connect to server {config.server_url}: {e}")

        print("Starting OIDC login flow...")
        profile_content = get_profile_with_oidc(config, args.output_auth_url)

        with open(config.output_path, 'wb') as f:
            f.write(profile_content)
        print(f"Successfully saved configuration to {config.output_path}")

    except Exception as e:
        print(f"Error: An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
