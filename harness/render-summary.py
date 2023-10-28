#!/usr/bin/env python

import argparse
import json
import os
from pathlib import Path
import sys

# render-summary.py: take a `results.json` from a harness run and render
# it as a GitHub Actions step summary, collating against `limbo.json`

if summary := os.getenv("GITHUB_STEP_SUMMARY"):
    _OUT = Path(summary).open("wt+")
else:
    _OUT = sys.stdout

_FAILED_RESULT_TEMPLATE = """
### ❌ `{testcase_id}`

* Expected result: {expected_result}
* Actual result: {actual_result}

{description}

Additional context: {context}
"""

_RESULT_ROW = "| {testcase_id} | {status} | {expected} | {actual} | {context} |"

def _render(s: str) -> None:
    print(f"{s}", file=_OUT)

parser = argparse.ArgumentParser()
parser.add_argument("limbo", type=Path)
parser.add_argument("results", type=Path)
args = parser.parse_args()

limbo = json.loads(args.limbo.read_text())
results = json.loads(args.results.read_text())

_render(f"## Limbo results for `{results["harness"]}`\n")

_render("""
| Testcase | Status | Expected | Actual | Context |
| -------- | ------ | -------- | ------ | ------- |"""
)

for result in results["results"]:
    testcase_id = result["id"]
    actual = result["actual_result"]
    context = result["context"]
    if not context:
        # Normalize missing context into an empty string.
        context = ""
    else:
        context = f"`{context}`"

    testcase = next(t for t in limbo["testcases"] if t["id"] == testcase_id)
    expected = testcase["expected_result"]
    description = testcase["description"]

    status = "✅" if expected == actual else "❌"

    row = _RESULT_ROW.format(
        testcase_id=testcase_id,
        status=status,
        expected=expected,
        actual=actual,
        context=context,
    )
    _render(row)
