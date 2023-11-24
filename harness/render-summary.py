#!/usr/bin/env python

import argparse
import json
import os
import sys
from pathlib import Path

# render-summary.py: take a `results.json` from a harness run and render
# it as a GitHub Actions step summary, collating against `limbo.json`

if summary := os.getenv("GITHUB_STEP_SUMMARY"):
    _OUT = Path(summary).open("wt+")
else:
    _OUT = sys.stdout

_RESULT_ROW = "| `{testcase_id}` | {status} | {expected} | {actual} | {context} |"


def _render(s: str) -> None:
    print(f"{s}", file=_OUT)


parser = argparse.ArgumentParser()
parser.add_argument("limbo", type=Path)
parser.add_argument("results", type=Path)
args = parser.parse_args()

limbo = json.loads(args.limbo.read_text())
results = json.loads(args.results.read_text())

_render(f"## Limbo results for `{results["harness"]}`\n")

_render(
    """
| Testcase | Status | Expected | Actual | Context |
| -------- | ------ | -------- | ------ | ------- |"""
)

for result in results["results"]:
    testcase_id = result["id"]
    actual = result["actual_result"]

    context = result["context"]
    context = f"`{context}`" if context else ""

    testcase = next(t for t in limbo["testcases"] if t["id"] == testcase_id)
    expected = testcase["expected_result"]
    description = testcase["description"]

    match (expected, actual):
        case ("SUCCESS", "SUCCESS") | ("FAILURE", "FAILURE"):
            status = "✅"
        case (_, "SKIPPED"):
            status = "🚧"
        case _:
            status = "❌"

    row = _RESULT_ROW.format(
        testcase_id=testcase_id,
        status=status,
        expected=expected,
        actual=actual,
        context=context,
    )
    _render(row)
