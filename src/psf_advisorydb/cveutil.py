"""Utility functions for cvelib"""

import os

from cvelib import cve_api


def client_from_env() -> cve_api.CveApi:
    return cve_api.CveApi(
        org=os.environ.get("CVE_ORG", "PSF"),
        username=os.environ["CVE_USERNAME"],
        api_key=os.environ["CVE_API_TOKEN"],
        env=os.environ.get("CVE_ENV", "prod"),
    )
