from unittest import mock

import pytest

from psf_advisorydb import cveutil


@pytest.fixture
def cve_env(monkeypatch):
    monkeypatch.setenv("CVE_USERNAME", "psf@example.org")
    monkeypatch.setenv("CVE_API_TOKEN", "psf_api_token")


def test_client_from_env(cve_env, monkeypatch):
    monkeypatch.setenv("CVE_ENV", "test")
    monkeypatch.setenv("CVE_ORG", "TestOrg")

    with mock.patch("cvelib.cve_api.CveApi", autospec=True) as cve_api:
        cveutil.client_from_env()

    cve_api.assert_called_once_with(
        org="TestOrg",
        username="psf@example.org",
        api_key="psf_api_token",
        env="test",
    )


def test_client_from_env_defaults(cve_env, monkeypatch):
    monkeypatch.delenv("CVE_ENV", raising=False)
    monkeypatch.delenv("CVE_ORG", raising=False)

    with mock.patch("cvelib.cve_api.CveApi", autospec=True) as cve_api:
        cveutil.client_from_env()

    cve_api.assert_called_once_with(
        org="PSF",
        username="psf@example.org",
        api_key="psf_api_token",
        env="prod",
    )
