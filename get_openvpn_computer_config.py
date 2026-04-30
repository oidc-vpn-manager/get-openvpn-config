#!/usr/bin/env python3
import os
import click
import requests
import yaml
from pathlib import Path


def _user_downloads_path():
    """Return the user's Downloads directory if it exists, else home dir.

    Avoids a hard runtime dep on the third-party ``platformdirs`` package so the
    script can be run as a single file via curl + python3 without pip-installing
    extras beyond what the rest of the script already needs (click/requests/PyYAML).
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
        self.user_config_path = _user_config_path or (Path.home() / ".config" / "ovpn-manager" / "config.yaml")
        self.system_config_path = _system_config_path or Path("/etc/ovpn-manager/config.yaml")

        self.user_config = self._load_config_file(self.user_config_path)
        self.system_config = self._load_config_file(self.system_config_path)

        self.server_url = self._resolve(server_url, 'OVPN_MANAGER_URL', 'server_url')
        self.output_path = self._resolve_output_path(output)
        self.overwrite = self._resolve_overwrite_flag(overwrite)

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
            Path: Resolved output file path for computer profile
        """
        path_str = self._resolve(cli_arg, 'OVPN_MANAGER_OUTPUT', 'output')
        if path_str:
            return Path(os.path.expanduser(path_str))
        try:
            downloads_dir = _user_downloads_path()
            return downloads_dir / "computer-config.ovpn"
        except Exception:
            return Path.home() / "computer-config.ovpn"

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

def get_computer_profile_with_psk(config, psk):
    """Handles PSK-based authentication for computer profile retrieval."""
    url = f"{config.server_url}/api/v1/computer/bundle"
    headers = {'Authorization': f'Bearer {psk}'}

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.content

# --- CLI Logic ---

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('-s', '--server-url', help='The base URL of the configuration server.')
@click.option('-o', '--output', help='Path to save the OVPN configuration file.')
@click.option('-f', '--force', is_flag=True, help='Overwrite the output file if it already exists.')
@click.option('--psk', required=True, envvar='OVPN_PSK', help='The pre-shared key for the computer.')
def main(server_url, output, force, psk):
    """Fetches an OpenVPN computer profile using PSK authentication for pre-determined configurations."""
    try:
        config = Config(server_url, output, force)

        if not config.server_url:
            raise click.ClickException("Server URL is not configured.")

        if config.output_path.exists() and not config.overwrite:
            raise click.ClickException(f"Output file '{config.output_path}' already exists. Use --force to overwrite.")

        click.echo("Requesting computer profile with PSK authentication...")
        profile_content = get_computer_profile_with_psk(config, psk)

        with open(config.output_path, 'wb') as f:
            f.write(profile_content)
        click.secho(f"Successfully saved computer configuration to {config.output_path}", fg="green")

    except Exception as e:
        raise click.ClickException(f"An error occurred: {e}")

if __name__ == '__main__':
    main()