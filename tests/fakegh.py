from collections import abc
from dataclasses import dataclass, field


@dataclass
class FakeGHIssue:
    body: str = ""

    @staticmethod
    def _pr_refs(*prnums: int) -> str:
        if not prnums:
            return ""
        return f"""
<!-- gh-linked-prs -->
{"\n".join(f"* gh-{pr}" for pr in prnums)}
<!-- /gh-linked-prs -->
"""


@dataclass
class FakeGHPR:
    merge_commit_sha: str | None = None

    @property
    def merged(self) -> bool:
        return bool(self.merge_commit_sha)


@dataclass
class FakeGHRepo:
    _issues: dict[int, FakeGHIssue] = field(default_factory=dict)
    _prs: dict[int, FakeGHPR] = field(default_factory=dict)

    def _add_issue(self, issue_num: int, pr_nums: abc.Iterable[int] = ()):
        if not (self._issues or pr_nums):
            # For ease of use, the first issue automatically references existing PRs.
            pr_nums = self._prs.keys()
        self._issues[issue_num] = FakeGHIssue(
            body=FakeGHIssue._pr_refs(*pr_nums),
        )

    def _add_pr(self, pr_num: int, merge_commit_sha: str | None = None):
        self._prs[pr_num] = FakeGHPR(merge_commit_sha)

    def get_issue(self, num: int) -> FakeGHIssue:
        return self._issues[num]

    def get_pull(self, num: int) -> FakeGHPR:
        return self._prs[num]


@dataclass
class FakeGithub:
    _repos: dict[str, FakeGHRepo] = field(default_factory=dict)

    @classmethod
    def _from_repo(cls, repo: FakeGHRepo, name: str = "python/cpython"):
        return cls({name: repo})

    def get_repo(self, full_name_or_id: str, lazy: bool = False):
        return self._repos[full_name_or_id]
