"""Configuration validation -- the guard rails that fail a bad deployment at startup."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cf_user_idm import CfAccessSettings, ConfigurationError


def test_reads_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CF_ACCESS_TEAM_DOMAIN", "acme")
    monkeypatch.setenv("CF_ACCESS_AUDIENCE", "aud-one")

    settings = CfAccessSettings(_env_file=None)

    assert settings.team_domain == "acme"
    assert settings.audience == ["aud-one"]
    assert settings.issuer == "https://acme.cloudflareaccess.com"
    assert settings.certs_url == "https://acme.cloudflareaccess.com/cdn-cgi/access/certs"
    assert settings.logout_url == "https://acme.cloudflareaccess.com/cdn-cgi/access/logout"


def test_audience_accepts_comma_separated_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CF_ACCESS_TEAM_DOMAIN", "acme")
    monkeypatch.setenv("CF_ACCESS_AUDIENCE", "aud-one, aud-two ,aud-three")

    settings = CfAccessSettings(_env_file=None)

    assert settings.audience == ["aud-one", "aud-two", "aud-three"]


@pytest.mark.parametrize(
    "raw",
    [
        "acme",
        "acme.cloudflareaccess.com",
        "https://acme.cloudflareaccess.com",
        "https://acme.cloudflareaccess.com/",
    ],
)
def test_team_domain_normalizes_every_accepted_spelling(raw: str) -> None:
    settings = CfAccessSettings(team_domain=raw, audience=["aud"], _env_file=None)
    assert settings.team_domain == "acme"


def test_team_domain_rejects_nonsense() -> None:
    with pytest.raises(ValidationError):
        CfAccessSettings(team_domain="not a team!", audience=["aud"], _env_file=None)


def test_missing_team_domain_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="CF_ACCESS_TEAM_DOMAIN"):
        CfAccessSettings(audience=["aud"], _env_file=None)


def test_missing_audience_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="CF_ACCESS_AUDIENCE"):
        CfAccessSettings(team_domain="acme", _env_file=None)


@pytest.mark.parametrize("environment", ["production", "PROD", "staging", " Production "])
def test_dev_mode_refuses_to_start_in_production_like_environments(environment: str) -> None:
    with pytest.raises(ConfigurationError, match="must never run in a production-like"):
        CfAccessSettings(
            dev_mode=True,
            dev_user_email="dev@localhost",
            app_env=environment,
            _env_file=None,
        )


def test_dev_mode_requires_an_email() -> None:
    with pytest.raises(ConfigurationError, match="CF_ACCESS_DEV_USER_EMAIL"):
        CfAccessSettings(dev_mode=True, app_env="development", _env_file=None)


def test_dev_mode_does_not_require_cloudflare_configuration() -> None:
    settings = CfAccessSettings(
        dev_mode=True, dev_user_email="dev@localhost", app_env="local", _env_file=None
    )
    assert settings.team_domain is None
    assert settings.audience == []


def test_app_env_falls_back_to_the_plain_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(ConfigurationError, match="must never run in a production-like"):
        CfAccessSettings(dev_mode=True, dev_user_email="dev@localhost", _env_file=None)


def test_router_prefix_must_be_a_path() -> None:
    with pytest.raises(ValidationError):
        CfAccessSettings(team_domain="acme", audience=["a"], router_prefix="auth", _env_file=None)
