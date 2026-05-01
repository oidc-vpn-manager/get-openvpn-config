#!/usr/bin/env python3
"""Fetches an OpenVPN computer profile using PSK authentication.

Stdlib-only CLI dependencies (argparse + json). Configuration files are JSON.
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests


def _user_downloads_path():
    """Return the user's Downloads directory if it exists, else home dir.

    Avoids a hard runtime dep on the third-party ``platformdirs`` package so the
    script can be run as a single file via curl + python3 without pip-installing
    extras beyond what the rest of the script already needs.
    """
    candidate = Path.home() / "Downloads"
    return candidate if candidate.is_dir() else Path.home()


# --- Configuration Logic ---

class Config:
    """
    Resolves client configuration from multiple sources in a defined order
    of precedence: CLI > Environment > User Config > System Config > Default.
    """
    def __init__(self, server_url=None, output=None, overwrite=None, _user_config_path=None, _system_config_path=None):
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.json")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.json")

        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        resolved_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')
        self.server_url = resolved_url.rstrip('/') if resolved_url else resolved_url
        self.output_path = self._resolve_output_path(output)
        self.overwrite = self._resolve_overwrite_flag(overwrite)

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
            return downloads_dir / "computer-config.ovpn"
        except Exception:
            return Path.home() / "computer-config.ovpn"

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

def get_computer_profile_with_psk(config, psk):
    """Handles PSK-based authentication for computer profile retrieval."""
    url = f"{config.server_url}/api/v1/computer/bundle"
    headers = {'Authorization': f'Bearer {psk}'}

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.content


# --- CLI Logic ---

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="get_openvpn_computer_config.py",
        description="Fetches an OpenVPN computer profile using PSK authentication for pre-determined configurations.",
    )
    parser.add_argument('-s', '--server-url', help='The base URL of the configuration server.')
    parser.add_argument('-o', '--output', help='Path to save the OVPN configuration file.')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite the output file if it already exists.')
    parser.add_argument('--psk', default=os.environ.get('OVPN_PSK'),
                        help='The pre-shared key for the computer. Can also be supplied via the OVPN_PSK environment variable.')
    return parser


def main(argv=None):
    """Entry point. Accepts optional argv list to support direct calls from tests."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.psk:
        parser.error("the following arguments are required: --psk")

    try:
        config = Config(args.server_url, args.output, args.force or None)

        if not config.server_url:
            raise RuntimeError("Server URL is not configured.")

        if config.output_path.exists() and not config.overwrite:
            raise RuntimeError(f"Output file '{config.output_path}' already exists. Use --force to overwrite.")

        print("Requesting computer profile with PSK authentication...")
        profile_content = get_computer_profile_with_psk(config, args.psk)

        with open(config.output_path, 'wb') as f:
            f.write(profile_content)
        print(f"Successfully saved computer configuration to {config.output_path}")

    except Exception as e:
        print(f"Error: An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
