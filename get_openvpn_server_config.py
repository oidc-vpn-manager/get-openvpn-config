#!/usr/bin/env python3
import os
import click
import requests
import yaml
import tarfile
import tempfile
from pathlib import Path

# --- Configuration Logic ---

class Config:
    """
    Resolves client configuration from multiple sources in a defined order
    of precedence: CLI > Environment > User Config > System Config > Default.
    """
    def __init__(self, server_url=None, _user_config_path=None, _system_config_path=None):
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.yaml")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.yaml")

        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        self.server_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')

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

    # Create target directory
    target_path.mkdir(parents=True, exist_ok=True)

    click.echo(f"Extracting files to {target_path}...")

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

                # Write file to destination
                with open(dest_path, 'wb') as f:
                    f.write(file_content)

                click.echo(f"Extracted {filename} -> {dest_path}")

    return {'target_dir': target_path}

# --- CLI Logic ---

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('-s', '--server-url', help='The base URL of the configuration server.')
@click.option('--target-dir', default='/etc/openvpn', help='Target directory for OpenVPN files (default: /etc/openvpn).')
@click.option('-f', '--force', is_flag=True, help='Overwrite existing files.')
@click.option('--psk', required=True, envvar='OVPN_PSK', help='The pre-shared key for the device.')
def main(server_url, target_dir, force, psk):
    """Fetches OpenVPN server configuration files using a Pre-Shared Key and extracts files to target directory."""
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

        extract_server_files(tar_content, target_path)

        click.secho(f"Successfully extracted server configuration files to {target_path}", fg="green")

    except Exception as e:
        raise click.ClickException(f"An error occurred: {e}")

if __name__ == '__main__':
    main()