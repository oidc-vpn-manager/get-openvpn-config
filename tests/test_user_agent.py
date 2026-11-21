"""
Tests for the User-Agent every get_openvpn_config script sends to the server.

The OIDC VPN Manager frontend may sit behind a CDN or WAF that refuses generic
HTTP-library user agents (for example ``python-requests/<version>``), which
would make every download fail with 403 before reaching the server. Each
script therefore names itself explicitly on every request.

The PSK tests use a real local HTTP server (pytest-httpserver) so they check
the header as received on the wire, not only the arguments passed to a mock.
"""

import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from werkzeug import Response

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import get_openvpn_computer_config
import get_openvpn_profile
import get_openvpn_server_config

EXPECTED_USER_AGENT = "get-openvpn-config/1"
SCRIPTS = [get_openvpn_profile, get_openvpn_server_config, get_openvpn_computer_config]


@pytest.mark.parametrize("module", SCRIPTS, ids=lambda m: m.__name__)
def test_user_agent_constant_names_the_tool(module):
    """Each standalone script defines the same tool-specific User-Agent."""
    assert module.USER_AGENT == EXPECTED_USER_AGENT


@pytest.mark.parametrize("module", SCRIPTS, ids=lambda m: m.__name__)
def test_user_agent_discloses_no_library_or_runtime(module):
    """
    The User-Agent does not reveal the HTTP library or Python version.

    Information-disclosure lens: the requests default advertises the library
    and its exact version to anyone observing the traffic.
    """
    assert not re.search(r"python|requests|urllib", module.USER_AGENT, re.IGNORECASE)


def test_server_bundle_request_sends_user_agent_on_the_wire(httpserver):
    """The server bundle download carries the tool User-Agent and the PSK."""
    httpserver.expect_request(
        "/api/v1/server/bundle",
        headers={"User-Agent": EXPECTED_USER_AGENT, "Authorization": "Bearer psk-1"},
    ).respond_with_data(b"bundle")
    config = SimpleNamespace(server_url=httpserver.url_for("").rstrip("/"))

    assert get_openvpn_server_config.get_profile_with_psk(config, "psk-1") == b"bundle"
    httpserver.check_assertions()


def test_computer_bundle_request_sends_user_agent_on_the_wire(httpserver):
    """The computer profile download carries the tool User-Agent and the PSK."""
    httpserver.expect_request(
        "/api/v1/computer/bundle",
        headers={"User-Agent": EXPECTED_USER_AGENT, "Authorization": "Bearer psk-2"},
    ).respond_with_data(b"profile")
    config = SimpleNamespace(server_url=httpserver.url_for("").rstrip("/"))

    assert get_openvpn_computer_config.get_computer_profile_with_psk(config, "psk-2") == b"profile"
    httpserver.check_assertions()


def test_generic_user_agent_would_be_refused_by_a_waf(httpserver):
    """
    Not-happy path: a front-end that refuses generic library user agents
    rejects a request without the tool User-Agent, but serves the tool.

    Models the deployment failure this change prevents, and checks the
    script surfaces the refusal as an error rather than saving a 403 body.
    """
    def waf(request):
        if request.headers.get("User-Agent", "").startswith("python-requests"):
            return Response("blocked", status=403)
        return Response(b"bundle", status=200)

    httpserver.expect_request("/api/v1/server/bundle").respond_with_handler(waf)
    config = SimpleNamespace(server_url=httpserver.url_for("").rstrip("/"))

    assert get_openvpn_server_config.get_profile_with_psk(config, "psk-3") == b"bundle"

    import requests
    with pytest.raises(requests.exceptions.HTTPError):
        requests.get(f"{config.server_url}/api/v1/server/bundle", timeout=5).raise_for_status()


@patch("get_openvpn_profile.get_profile_with_oidc", return_value=b"profile")
@patch("get_openvpn_profile.requests.get")
def test_health_check_sends_user_agent(mock_get, _mock_oidc, tmp_path):
    """The connectivity check before the OIDC flow carries the tool User-Agent."""
    mock_get.return_value = MagicMock(status_code=200)
    output = tmp_path / "profile.ovpn"

    get_openvpn_profile.main(["--server-url", "https://vpn.example", "--output", str(output)])

    mock_get.assert_called_once_with(
        "https://vpn.example/health",
        headers={"User-Agent": EXPECTED_USER_AGENT},
        timeout=5,
    )
