"""
Utilities for interacting with GitHub and GitHub Actions.

These utilities assume that they're being run from GitHub Actions,
with a sufficiently permissioned `GITHUB_TOKEN`.
"""

import json
import os
from functools import cache
from pathlib import Path
from typing import Any

import requests


@cache
def github_token() -> str:
    return os.environ["GITHUB_TOKEN"]


@cache
def github_event() -> dict[str, Any]:
    return json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())


def comment(msg: str) -> None:
    event = github_event()
    if "pull_request" not in event:
        raise ValueError("wrong GitHub event: need pull_request")

    number = event["number"]
    repo = event["repository"]["full_name"]
    url = f"https://api.github.com/repos/{repo}/issues/{number}/comments"

    requests.post(
        url,
        headers={
            "Authorization": github_token(),
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={"body": msg},
    )
