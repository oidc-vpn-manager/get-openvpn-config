#!/usr/bin/env python3
"""Fetches OpenVPN server configuration files using a Pre-Shared Key.

Stdlib-only CLI dependencies (argparse + json) so the script can run on a
stock distro install with nothing more than ``python3`` plus ``requests``.
Configuration files are JSON.
"""
import argparse
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path

import requests


# --- Configuration Logic ---

class Config:
    """
    Resolves client configuration from multiple sources in a defined order
    of precedence: CLI > Environment > User Config > System Config > Default.
    """
    def __init__(self, server_url=None, _user_config_path=None, _system_config_path=None):
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.json")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.json")

        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        resolved_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')
        self.server_url = resolved_url.rstrip('/') if resolved_url else resolved_url

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


# --- API Client Logic ---

def get_profile_with_psk(config, psk):
    """Handles PSK-based authentication for server bundle retrieval."""
    url = f"{config.server_url}/api/v1/server/bundle"
    headers = {'Authorization': f'Bearer {psk}'}

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.content


def extract_server_files(tar_content, target_dir):
    """
    Extracts tar file contents to the target directory.
    Server provisioner will decide final placement of files.
    """
    target_path = Path(target_dir)

    target_path.mkdir(parents=True, exist_ok=True)

    print(f"Extracting files to {target_path}...")

    with tempfile.NamedTemporaryFile() as temp_tar:
        temp_tar.write(tar_content)
        temp_tar.flush()

        with tarfile.open(temp_tar.name, 'r') as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue

                filename = Path(member.name).name
                file_content = tar.extractfile(member).read()
                dest_path = target_path / filename

                with open(dest_path, 'wb') as f:
                    f.write(file_content)

                print(f"Extracted {filename} -> {dest_path}")

    return {'target_dir': target_path}


# --- CLI Logic ---

def _build_parser():
    parser = argparse.ArgumentParser(
        prog="get_openvpn_server_config.py",
        description="Fetches OpenVPN server configuration files using a Pre-Shared Key and extracts files to target directory.",
    )
    parser.add_argument('-s', '--server-url', help='The base URL of the configuration server.')
    parser.add_argument('--target-dir', default='/etc/openvpn',
                        help='Target directory for OpenVPN files (default: /etc/openvpn).')
    parser.add_argument('-f', '--force', action='store_true', help='Overwrite existing files.')
    parser.add_argument('--psk', default=os.environ.get('OVPN_PSK'),
                        help='The pre-shared key for the device. Can also be supplied via the OVPN_PSK environment variable.')
    return parser


def main(argv=None):
    """Entry point. Accepts optional argv list to support direct calls from tests."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.psk:
        parser.error("the following arguments are required: --psk")

    try:
        config = Config(args.server_url)

        if not config.server_url:
            raise RuntimeError("Server URL is not configured.")

        target_path = Path(args.target_dir)

        if not args.force and target_path.exists():
            existing_files = list(target_path.rglob('*'))
            if existing_files:
                raise RuntimeError(f"Target directory '{target_path}' contains files. Use --force to overwrite.")

        print("Requesting server profile...")
        tar_content = get_profile_with_psk(config, args.psk)

        extract_server_files(tar_content, target_path)

        print(f"Successfully extracted server configuration files to {target_path}")

    except Exception as e:
        print(f"Error: An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
