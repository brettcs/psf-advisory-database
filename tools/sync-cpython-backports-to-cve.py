"""
Script for keeping CVE 'affected' versions up-to-date with CPython backports

Requires the following environment variables:
* CPYTHON_REPO:     Path to a local checkout of a CPython repository.
* GH_API_TOKEN:     API token with read permissions for the 'python/cpython' repo.
* CVE_API_TOKEN:    API token for CVE services.
* CVE_USERNAME:     Username for CVE services.
* CVE_ENV:          CVE services environment. Defaults to 'prod', but can be 'test'.
                    Note that the 'CVE_API_TOKEN' is different between environments.
* DRY_RUN:          This value must be set to '0' for updates to persist to CVE services.
"""

import dataclasses
import datetime
import os
import re
import subprocess
import typing

import urllib3
from cvelib.cve_api import CveApi
from github import Auth as GitHubAuth
from github import Github
from packaging.version import Version as PackagingVersion

AffectedVersion: typing.TypeAlias = str
CveAffectedVersionPair: typing.TypeAlias = tuple[AffectedVersion, AffectedVersion]
CveAffectedVersionPairs: typing.TypeAlias = list[CveAffectedVersionPair]
CveRecord: typing.TypeAlias = dict[str, typing.Any]
GitCommitSha: typing.TypeAlias = str


def get_merged_commit_shas_for_issue(
    gh_api: Github, gh_issue_number: int
) -> set[GitCommitSha]:
    """
    Gets a set of all git commit SHAs that have been merged for a given GitHub issue.
    This function relies on Bedevere's specific format for including referenced pull requests.
    """
    gh_repo = gh_api.get_repo(
        full_name_or_id="python/cpython",
        lazy=True,  # Don't request the repo to avoid an API call.
    )

    # If the necessary metadata from bedevere isn't in
    # the issue then we give up. This metadata should always be there.
    body = gh_repo.get_issue(gh_issue_number).body
    gh_linked_prs_start = body.find("<!-- gh-linked-prs -->")
    gh_linked_prs_end = body.find("<!-- /gh-linked-prs -->")
    if gh_linked_prs_start == -1 or gh_linked_prs_end == -1:
        linked_prs_numbers = []
    else:
        linked_prs_body = body[gh_linked_prs_start:gh_linked_prs_end]
        linked_prs_numbers = map(int, re.findall(r"\* gh-([0-9]+)", linked_prs_body))

    # Now we figure out which PRs are merged and what their commit SHAs are.
    commit_shas = set()
    for linked_pr_number in linked_prs_numbers:
        if commit_sha := get_merged_commit_shas_for_pr(gh_api, linked_pr_number):
            commit_shas.add(commit_sha)

    return commit_shas


def get_merged_commit_shas_for_pr(gh_api: Github, pr_number: int) -> str | None:
    gh_repo = gh_api.get_repo(
        full_name_or_id="python/cpython",
        lazy=True,  # Don't request the repo to avoid an API call.
    )

    # Some git commit SHAs that aren't part of a vuln fix, instead
    # they're things like additional tests, etc. We want to ignore those to
    # avoid giving a "fixed" version that's beyond where the actual fix is.
    ignored_commit_shas = {
        "10e9bb13b8dcaa414645b9bd10718d8f7179e82b",
    }

    gh_pr = gh_repo.get_pull(pr_number)
    if (
        gh_pr.merged
        and gh_pr.merge_commit_sha
        and gh_pr.merge_commit_sha not in ignored_commit_shas
    ):
        return gh_pr.merge_commit_sha
    return None


def sorted_version_tuples(value: CveAffectedVersionPairs) -> CveAffectedVersionPairs:
    """Sort a list of (greaterOrEqual, lessThan) version pairs"""
    return sorted(value, key=lambda x: [PackagingVersion(y) for y in x])


def get_git_tags_for_commit_sha(
    cpython_repo: str, commit_sha: GitCommitSha
) -> set[str]:
    """Get all tags that the commit appears in."""
    try:
        commit_sha_in_tags = (
            subprocess.check_output(
                ["git", "tag", "--contains", commit_sha],
                cwd=cpython_repo,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
            .split()
        )
    except subprocess.CalledProcessError:
        return set()

    return {
        git_tag
        for git_tag in commit_sha_in_tags
        if re.search(r"\Av[0-9]+\.[0-9]+\.", git_tag)
    }


def get_all_git_tags(cpython_repo: str) -> set[str]:
    """Get all version tags"""
    try:
        git_tags = (
            subprocess.check_output(
                ["git", "tag", "-l"],
                cwd=cpython_repo,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
            .split()
        )
    except subprocess.CalledProcessError:
        return set()
    return {
        git_tag for git_tag in git_tags if re.search(r"\Av[0-9]+\.[0-9]+\.", git_tag)
    }


def create_cve_affected_versions_from_commit_shas(
    commit_shas: typing.Iterable[GitCommitSha], cpython_repo: str
) -> CveAffectedVersionPairs:
    """Gets the list of affected versions of CPython"""

    fixed_minor_versions: dict[str, PackagingVersion] = {}
    affected_minor_versions: dict[str, set[PackagingVersion]] = {}
    all_affected_versions: set[PackagingVersion] = set()
    all_fixed_versions: set[PackagingVersion] = set()

    affected_tags = get_all_git_tags(cpython_repo)
    for commit_sha in commit_shas:
        fixed_tags = get_git_tags_for_commit_sha(cpython_repo, commit_sha)
        affected_tags -= fixed_tags

        for fixed_tag in fixed_tags:
            fixed_version = PackagingVersion(
                re.search(r"\Av([0-9]+\.[0-9]+\.[0-9]+.*)\Z", fixed_tag).group(1)
            )
            all_fixed_versions.add(fixed_version)
            minor_version = f"{fixed_version.major}.{fixed_version.minor}"

            fixed_minor_versions.setdefault(minor_version, fixed_version)
            if fixed_version < fixed_minor_versions[minor_version]:
                fixed_minor_versions[minor_version] = fixed_version

    for affected_tag in affected_tags:
        affected_version = PackagingVersion(
            re.search(r"\Av([0-9]+\.[0-9]+\.[0-9]+.*)\Z", affected_tag).group(1)
        )
        all_affected_versions.add(affected_version)
        minor_version = f"{affected_version.major}.{affected_version.minor}"
        affected_minor_versions.setdefault(minor_version, set()).add(affected_version)

    # Create 'affected' tuples based on fixed versions.
    cve_affected_versions = []
    for affected_minor_version, affected_versions in affected_minor_versions.items():
        if affected_minor_version in fixed_minor_versions:
            fixed_version = fixed_minor_versions[affected_minor_version]
            if fixed_version.is_prerelease:
                earliest_affected_version = min(affected_versions)
            else:
                earliest_affected_version = min(
                    v for v in affected_versions if not v.is_prerelease
                )
            cve_affected_versions.append(
                (str(earliest_affected_version), str(fixed_version))
            )

    cve_affected_versions = sorted_version_tuples(cve_affected_versions)

    # If there are affected versions beyond the newest
    # fixed version then we need to extend the affected
    # list out to include the newest version of Python.
    if all_fixed_versions:
        newest_fixed_version = max(all_fixed_versions)
    else:
        newest_fixed_version = PackagingVersion("0.0.0")
    newer_affected_versions = {
        v for v in all_affected_versions if v > newest_fixed_version
    }
    if newer_affected_versions:
        cve_affected_versions.append(
            (
                str(min(newer_affected_versions)),
                str(get_next_python_version(cpython_repo)),
            )
        )

    # Replace the first tuple with ('0', fix-version)
    if cve_affected_versions:
        cve_affected_versions[0] = ("0", cve_affected_versions[0][1])

    return cve_affected_versions


def get_all_python_minor_versions(cpython_repo: str) -> set[str]:
    minor_versions = set()
    for git_tag in (
        subprocess.check_output(
            ["git", "tag", "--list"],
            cwd=cpython_repo,
            stderr=subprocess.DEVNULL,
        )
        .decode()
        .strip()
        .split()
    ):
        if not (match := re.search(r"\Av([0-9]+\.[0-9]+)\.", git_tag)):
            continue
        minor_versions.add(match.group(1))
    return minor_versions


def get_next_python_version(cpython_repo: str) -> PackagingVersion:
    git_tags: list[PackagingVersion] = []
    for git_tag in (
        subprocess.check_output(
            ["git", "tag", "--list"],
            cwd=cpython_repo,
            stderr=subprocess.DEVNULL,
        )
        .decode()
        .strip()
        .split()
    ):
        if not (match := re.search(r"\Av([0-9]+\.[0-9]+\.[0-9abrc]+)\Z", git_tag)):
            continue
        git_tags.append(PackagingVersion(match.group(1)))
    version = sorted(git_tags)[-1]
    if version.is_prerelease:
        return PackagingVersion(f"{version.major}.{version.minor}.{version.micro}")
    else:
        return PackagingVersion(f"{version.major}.{version.minor}.{version.micro + 1}")


_OLDEST_ACTIVE_PYTHON_RELEASE: PackagingVersion | None = None


def get_oldest_active_python_release() -> PackagingVersion:
    """Fetch the set of currently active Python releases. We don't
    change information about inactive releases of Python from CVEs.
    """
    global _OLDEST_ACTIVE_PYTHON_RELEASE
    if _OLDEST_ACTIVE_PYTHON_RELEASE is None:
        http = urllib3.PoolManager()
        resp = http.request("GET", "https://peps.python.org/api/python-releases.json")
        if resp.status != 200:
            raise RuntimeError("Error while fetching Python release status")
        active_releases: set[PackagingVersion] = set()
        for release_major_minor, release in resp.json()["metadata"].items():
            if release["status"] == "end-of-life":
                continue
            active_releases.add(PackagingVersion(release_major_minor))
        _OLDEST_ACTIVE_PYTHON_RELEASE = min(active_releases)
    return _OLDEST_ACTIVE_PYTHON_RELEASE


def get_published_cves_for_cpython(cve_api: CveApi) -> dict[str, CveRecord]:
    # Iterate over the list of published CVEs
    cves = {}
    for cve_ref in cve_api.list_cves(state="PUBLISHED"):
        cve_id = cve_ref["cve_id"]
        cve_record = cve_api.show_cve_record(cve_id)

        # Skip non-CPython CVEs
        if not any(
            affected["product"] == "CPython"
            for affected in cve_record["containers"]["cna"]["affected"]
        ):
            continue

        cves[cve_id] = cve_record
    return cves


def get_cve_affected_versions(cve_record: CveRecord) -> CveAffectedVersionPairs:
    """We have two possible configuration of CVEs 'affected' field,
    either all versions are affected or there are some unaffected versions.
    """

    # There must only be one 'affected' entry, CPython.
    assert len(cve_record["containers"]["cna"]["affected"]) == 1

    cve_affected = []
    cve_versions = cve_record["containers"]["cna"]["affected"][0]["versions"]
    cve_default_affected_status = cve_record["containers"]["cna"]["affected"][0][
        "defaultStatus"
    ]

    # If the default status is 'affected' then we expect a single
    # version range that includes all versions being affected.
    if cve_default_affected_status == "affected":
        assert len(cve_versions) == 1
        assert cve_versions[0] == {}

    # If the default status is 'unaffected' then we should
    # expect version ranges to return back.
    else:
        assert cve_default_affected_status == "unaffected"
        for cve_version in cve_versions:
            assert cve_version["versionType"] == "python"
            assert "version" in cve_version

            if "lessThan" in cve_version:
                less_than_version = cve_version["lessThan"]
            else:
                assert "lessThanOrEqual" in cve_version, repr(cve_record)
                pkg_version = PackagingVersion(cve_version["lessThanOrEqual"])
                if pkg_version.is_prerelease:
                    less_than_version = f"{pkg_version.major}.{pkg_version.minor}.0"
                else:
                    pkg_version_micro = pkg_version.micro + 1
                    less_than_version = (
                        f"{pkg_version.major}.{pkg_version.minor}.{pkg_version_micro}"
                    )

            cve_affected.append((cve_version["version"], less_than_version))

    return sorted_version_tuples(cve_affected)


def get_cve_gh_issues_and_commit_shas(
    cve_record: CveRecord,
) -> tuple[list[int], set[GitCommitSha]]:
    # Only used for raising errors.
    cve_id = cve_record["cveMetadata"]["cveId"]

    # Find the 'issue-tracking' reference which we'll use to
    # gather the list of pull requests.
    gh_issue_url_re = re.compile(
        r"^https://github\.com/python/cpython/issues?/([0-9]+)$"
    )
    gh_pr_url_re = re.compile(r"^https://github\.com/python/cpython/pulls?/([0-9]+)$")
    gh_issue_numbers = []

    # Also find all currently referenced patches.
    gh_commit_url_re = re.compile(
        r"^https://github\.com/python/cpython/commit/([a-f0-9]{40,})$"
    )
    cve_reference_commit_shas = set()

    for ref in cve_record["containers"]["cna"]["references"]:
        # There must be exactly one GitHub issue per CVE.
        if "issue-tracking" in ref.get("tags", []) and (
            match := gh_issue_url_re.match(ref["url"])
        ):
            gh_issue_numbers.append(int(match.group(1)))

        # There can be many patches referenced in a CVE.
        if ref.get("tags") == ["patch"] and (
            match := gh_commit_url_re.match(ref["url"])
        ):
            cve_reference_commit_shas.add(match.group(1))

    if not gh_issue_numbers and not cve_reference_commit_shas:
        print(f"Couldn't find GitHub tracking issue(s) for {cve_id}")

    return gh_issue_numbers, cve_reference_commit_shas


def main():
    # Configuration
    CPYTHON_REPO = os.environ["CPYTHON_REPO"]
    GH_API_TOKEN = os.environ["GH_API_TOKEN"]
    CVE_API_TOKEN = os.environ["CVE_API_TOKEN"]
    CVE_USERNAME = os.environ["CVE_USERNAME"]
    CVE_ENV = os.environ.get("CVE_ENV", "prod")
    DRY_RUN = bool("DRY_RUN" in os.environ)

    # Services
    GH_API = Github(auth=GitHubAuth.Token(GH_API_TOKEN))
    CVE_API = CveApi(
        org="PSF",
        username=CVE_USERNAME,
        api_key=CVE_API_TOKEN,
        env=CVE_ENV,
    )

    if DRY_RUN:
        print("Script is in dry-run mode, updates won't be persisted to CVE services.")

    cves = get_published_cves_for_cpython(CVE_API)
    for cve_id, cve_record in sorted(cves.items(), reverse=True):
        updated_cve = False

        # Find the expected GitHub issue from the CVE.
        gh_issue_numbers, cve_commit_shas = get_cve_gh_issues_and_commit_shas(
            cve_record
        )
        if not gh_issue_numbers and not cve_commit_shas:
            continue

        # Get all fix commit SHAs
        if gh_issue_numbers:
            gh_commit_shas = set()
            for gh_issue_number in gh_issue_numbers:
                gh_commit_shas = get_merged_commit_shas_for_issue(
                    GH_API, gh_issue_number
                )

                # Figure out which commit SHAs aren't already referenced
                # and add them to the list of references.
                for commit_sha in sorted(gh_commit_shas):
                    if commit_sha not in cve_commit_shas:
                        cve_record["containers"]["cna"]["references"].append(
                            {
                                "tags": ["patch"],
                                "url": f"https://github.com/python/cpython/commit/{commit_sha}",
                            }
                        )
                        print(
                            f"Added reference to {cve_id} for commit SHA {commit_sha}"
                        )
                        updated_cve = True

                gh_commit_shas |= cve_commit_shas

        # If there aren't any GitHub issues to discover we go with what CVE has.
        else:
            gh_commit_shas = cve_commit_shas

        # Create the expected affected versions and actual to compare.
        expected_affected_versions = create_cve_affected_versions_from_commit_shas(
            commit_shas=gh_commit_shas, cpython_repo=CPYTHON_REPO
        )
        actual_affected_versions = get_cve_affected_versions(cve_record)

        # This means that there are no "fixed" versions released yet
        # so we use the "latest" version as our upper bound.
        if not expected_affected_versions:
            latest_python_version = get_next_python_version(CPYTHON_REPO)
            expected_affected_versions = [("0", str(latest_python_version))]

        # If the minimum affected version isn't "0" we want
        # to preserve that from the CVE, not from git commit data.
        if (
            expected_affected_versions
            and actual_affected_versions
            and actual_affected_versions[0][0] != "0"
        ):
            min_affected_version = PackagingVersion(actual_affected_versions[0][0])
            expected_affected_versions = [
                vers
                for vers in expected_affected_versions
                if all(PackagingVersion(v) < min_affected_version for v in vers)
            ]
            expected_affected_versions[0] = (
                str(min_affected_version),
                expected_affected_versions[0][1],
            )

        # Update the CVE affected versions if there's a difference.
        if (
            actual_affected_versions != expected_affected_versions
            and expected_affected_versions
        ):
            # Coherence check prior to setting affected versions on CVEs.
            assert all(
                PackagingVersion(lt) <= PackagingVersion(gt)
                for lt, gt in expected_affected_versions
            )
            assert expected_affected_versions == sorted_version_tuples(
                expected_affected_versions
            )

            print(
                f"Updated affected versions of {cve_id} from "
                f"{actual_affected_versions} to {expected_affected_versions}"
            )
            cve_record["containers"]["cna"]["affected"][0]["versions"] = [
                {
                    "version": lt_version,
                    "lessThan": gt_version,
                    "status": "affected",
                    "versionType": "python",
                }
                for lt_version, gt_version in expected_affected_versions
            ]
            updated_cve = True

        if updated_cve:
            if not DRY_RUN:
                CVE_API.update_published(
                    cve_id=cve_id, cve_json=cve_record, validate=True
                )
        else:
            print(f"{cve_id} is up-to-date with GitHub metadata")


if __name__ == "__main__":
    main()
