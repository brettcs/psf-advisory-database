import copy
import os
import subprocess

import pytest

from psf_advisorydb import cpython2cve

from .fakecve import FakeCveApi
from .fakegh import FakeGHRepo, FakeGithub

CPYTHON_URL = "https://github.com/cpython/python"


@pytest.fixture(scope="module", autouse=True)
def cpython_repo(tmp_path_factory):
    if "CPYTHON_REPO" in os.environ:
        return
    repo_path = tmp_path_factory.getbasetemp() / "cpython.git"
    if not repo_path.exists():
        subprocess.run(
            ["git", "clone", "--bare", "--tags", "--", CPYTHON_URL, str(repo_path)],
            check=True,
        )
    os.environ["CPYTHON_REPO"] = str(repo_path)


@pytest.fixture
def cve_2026_9669():
    repo = FakeGHRepo()
    repo._add_pr(150600, "5755d0f083949ff3c5bf3a37e673e24e306b036e")
    repo._add_pr(151045, "d3ca26983dfbccdf609f24ff5877dc3118e4702d")
    repo._add_pr(151054, "157a5df8cb5d82b33f918a7489e72ce95ceb12b6")
    repo._add_pr(151055, "619a12b2e545391dc436b3af79dda22337382a6f")
    repo._add_pr(151057, "991e6cf86496718c4ef00b362d640e00cb5c85b2")
    repo._add_pr(151132, "1ba6135eae75ad8413413caeeedb56ae72320636")
    repo._add_pr(151133, "938ec030e90c5e53f1faac6fab1643f14e4f4a79")
    repo._add_issue(150599)
    gh_api = FakeGithub._from_repo(repo)
    cve_api = FakeCveApi._from_files("CVE-2026-9669")
    return cve_api, gh_api


def test_cve_unchanged(cve_2026_9669):
    cve_api, gh_api = cve_2026_9669
    expected = cve_api.show_cve_record("CVE-2026-9669")
    cpython2cve.main(cve_api, gh_api)
    assert cve_api._records["CVE-2026-9669"] == expected


def test_cve_ranges_set(cve_2026_9669):
    cve_api, gh_api = cve_2026_9669
    expected = cve_api.show_cve_record("CVE-2026-9669")
    for aff in cve_api._records["CVE-2026-9669"]["containers"]["cna"]["affected"]:
        aff["versions"] = [
            {
                "lessThan": "3.15.0",
                "status": "affected",
                "version": "0",
                "versionType": "python",
            },
        ]
    cpython2cve.main(cve_api, gh_api)
    assert cve_api._records["CVE-2026-9669"] == expected
