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

        requests.patch(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": msg},
        ).raise_for_status()
    else:
        url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"
        logger.info(f"leaving a comment on {repo} #{number}")

        requests.post(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"body": msg},
        ).raise_for_status()


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
    resp.raise_for_status()

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
        requests.post(
            url,
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            json={"labels": add},
        ).raise_for_status()

    for label in remove:
        logger.info(f"removing label:{label} from {repo} #{number}")
        resp = requests.delete(
            f"{url}/{label}",
            headers={
                "Authorization": f"Bearer {github_token()}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

        # 404 is expected if the label doesn't exist
        if resp.status_code != 404:
            resp.raise_for_status()


def has_label(label: str) -> bool:
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/labels"

    resp = requests.get(url)
    resp.raise_for_status()

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
