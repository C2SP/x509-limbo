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

def _render(s: str) -> None:
    print(f"{s}\n", file=_OUT)

parser = argparse.ArgumentParser()
parser.add_argument("limbo", type=Path)
parser.add_argument("results", type=Path)
args = parser.parse_args()

limbo = json.loads(args.limbo.read_text())
results = json.loads(args.results.read_text())

_render(f"## Limbo results for `{results["harness"]}`")

for result in results["results"]:
    testcase_id = result["id"]
    actual_result = result["actual_result"]
    context = result["context"]

    testcase = next(t for t in limbo["testcases"] if t["id"] == testcase_id)
    expected_result = testcase["expected_result"]
    description = testcase["description"]

    if actual_result == expected_result:
        continue

    summary = _FAILED_RESULT_TEMPLATE.format(
        testcase_id=testcase_id,
        expected_result=expected_result,
        actual_result=actual_result,
        description=description,
        context=context,
    )
    _render(summary)
