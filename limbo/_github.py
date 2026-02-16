"""
Utilities for interacting with GitHub and GitHub Actions.

These utilities assume that they're being run from GitHub Actions,
with a sufficiently permissioned `GITHUB_TOKEN`.
"""

import json
import logging
import os
from functools import cache
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)


def _check_response(resp: requests.Response, *, allow_404: bool = False) -> bool:
    """
    Check a response for errors, handling permission errors gracefully.

    For PRs from third-party forks, the GITHUB_TOKEN has restricted permissions
    and write operations will fail with 403. This function logs a warning
    instead of raising an exception in that case.

    Args:
        resp: The response to check.
        allow_404: If True, treat 404 as a non-error (for idempotent deletes).

    Returns:
        True if the request succeeded, False if it failed due to permissions.

    Raises:
        requests.HTTPError: For non-permission-related errors.
    """
    if resp.ok:
        return True

    if allow_404 and resp.status_code == 404:
        return True

    if resp.status_code == 403:
        logger.warning(
            f"Insufficient permissions for {resp.request.method} {resp.request.url} "
            f"(this is expected for PRs from third-party forks)"
        )
        return False

    resp.raise_for_status()
    return False  # unreachable, but satisfies type checker


REGRESSIONS_LABEL = ":skull: regressions"
NO_REGRESSIONS_LABEL = ":see_no_evil: no-regressions"


@cache
def github_token() -> str:
    return os.environ["GITHUB_TOKEN"]


@cache
def github_event() -> dict[str, Any]:
    return json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())  # type: ignore[no-any-return]


def comment(msg: str, *, update: str | None = None) -> None:
    """
    Create or update a comment.

    If `update` is given, first attempt to update a comment that contains the given string.
    """
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]

    comment_id = None
    if update:
        comment_id = find_comment(update)

    if comment_id:
        url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
        logger.info(f"updating comment {comment_id} on {repo} #{number}")

        resp = requests.patch(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": msg},
        )
        _check_response(resp)
    else:
        url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"
        logger.info(f"leaving a comment on {repo} #{number}")

        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": msg},
        )
        _check_response(resp)


def find_comment(token: str) -> int | None:
    """
    Finds the first comment on the current PR containing the given token.
    Returns the ID of the matching comment, or `None` if no comments match.

    Assumes that the comment is present in the first 100 comments on the PR.
    """
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"

    resp = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {github_token()}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        params={"per_page": 100},
    )
    if not _check_response(resp):
        return None

    comments = resp.json()
    for comment in comments:
        if token in comment["body"]:
            return comment["id"]  # type: ignore[no-any-return]
    return None


def label(*, add: list[str], remove: list[str]) -> None:
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/labels"

    if add:
        logger.info(f"adding labels to {repo} #{number}: {add}")
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"labels": add},
        )
        _check_response(resp)

    for lbl in remove:
        logger.info(f"removing label:{lbl} from {repo} #{number}")
        resp = requests.delete(
            f"{url}/{lbl}",
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        _check_response(resp, allow_404=True)


def has_label(label: str) -> bool:
    """
    Check if the current PR has a given label.

    Returns False if the label is not present or if permissions are insufficient.
    """
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/labels"

    resp = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {github_token()}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if not _check_response(resp):
        return False

    labels = resp.json()
    return any(lbl["name"] == label for lbl in labels)


@cache
def workflow_url() -> str:
    url = os.getenv("GITHUB_SERVER_URL")
    repo = os.getenv("GITHUB_REPOSITORY")
    run_id = os.getenv("GITHUB_RUN_ID")
    return f"{url}/{repo}/actions/runs/{run_id}"


def step_summary(contents: str) -> None:
    Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(contents)
