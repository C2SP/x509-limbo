import argparse
import contextlib
import fnmatch
import json
import logging
import os
import random
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import requests
from pydantic import TypeAdapter
from pydantic.json_schema import models_json_schema

from limbo import _github, testcases
from limbo.testcases import bettertls, online

from . import __version__
from .models import ActualResult, Limbo, LimboResult

logging.basicConfig()
logger = logging.getLogger(__name__)

# NOTE: We configure the top package logger, rather than the root logger,
# to avoid overly verbose logging in third-party code by default.
package_logger = logging.getLogger("limbo")
package_logger.setLevel(os.environ.get("LIMBO_LOGLEVEL", "INFO").upper())


def main() -> None:
    parser = argparse.ArgumentParser(description="A self-management tool for x509-limbo")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(required=True)

    # `limbo schema`
    schema = subparsers.add_parser("schema", help="Dump the top-level JSON Schema for x509-limbo")
    schema.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="The path to write the schema to"
    )
    schema.set_defaults(func=_schema)

    # `limbo online-cases`
    online_cases = subparsers.add_parser(
        "online-cases", help="Regenerate cached testcases made from online requests"
    )
    online_cases.set_defaults(func=_online_cases)

    # `limbo compile`
    compile = subparsers.add_parser(
        "compile", help="Generate all testcases and produce a single JSON test suite"
    )
    compile.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="The path to write the testcase suite to"
    )
    compile.add_argument("--online", action="store_true", help="Regenerate cached online testcases")
    compile.add_argument("-f", "--force", action="store_true", help="Overwrite any existing output")
    compile.set_defaults(func=_compile)

    # `limbo harness`
    harness = subparsers.add_parser("harness", help="Run the given test harness")
    harness.add_argument(
        "--limbo",
        default=Path("limbo.json"),
        type=Path,
        metavar="FILE",
        help="The limbo testcase suite to load from",
    )
    harness.add_argument(
        "--output",
        default=Path("results.json"),
        type=Path,
        metavar="FILE",
        help="The path to write the harness's results to",
    )
    harness.add_argument(
        "--include",
        type=str,
        help="Include only testcases matching the given fnmatch(2)-style pattern",
    )
    harness.add_argument(
        "--exclude",
        type=str,
        help="Exclude any testcases matching the given fnmatch(2)-style pattern",
    )
    harness.add_argument("harness", type=str, help="The harness to execute")
    harness.set_defaults(func=_harness)

    # `limbo regression`
    regression = subparsers.add_parser(
        "regression", help="Run regression checks against the last result set"
    )
    regression.add_argument(
        "--current",
        type=Path,
        default=Path("results"),
        metavar="DIR",
        help="The current results to check against",
    )
    regression.set_defaults(func=_regression)

    args = parser.parse_args()
    args.func(args)


def _schema(args: argparse.Namespace) -> None:
    io = args.output.open(mode="w") if args.output else sys.stdout

    with contextlib.closing(io):
        top = models_json_schema([(Limbo, "validation")], title="x509-limbo schemas")[1]
        print(json.dumps(top, indent=2), file=io)


def _online_cases(args: argparse.Namespace) -> None:
    online.compile()


def _compile(args: argparse.Namespace) -> None:
    if args.online:
        online.compile()

    bettertls.register_testcases()
    online.register_testcases()

    all_testcases = [testcase() for _, testcase in testcases.registry.items()]
    combined = Limbo(version=1, testcases=all_testcases)

    io = args.output.open(mode="w") if args.output else sys.stdout
    with contextlib.closing(io):
        print(combined.model_dump_json(indent=2), file=io)


def _harness(args: argparse.Namespace) -> None:
    args.output.parent.mkdir(exist_ok=True)

    limbo_json = args.limbo.read_text()
    if args.include is not None or args.exclude is not None:
        testcases = Limbo.model_validate_json(limbo_json).testcases
        if args.include:
            testcases = [tc for tc in testcases if fnmatch.fnmatch(tc.id, args.include)]
        if args.exclude:
            testcases = [tc for tc in testcases if not fnmatch.fnmatch(tc.id, args.exclude)]
        limbo_json = Limbo(version=1, testcases=testcases).json()

    try:
        result = subprocess.run(
            [args.harness], input=limbo_json, encoding="utf-8", capture_output=True, check=True
        )
        args.output.write_text(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr, file=sys.stderr)


def _regression(args: argparse.Namespace) -> None:
    previous_results = TypeAdapter(list[LimboResult]).validate_python(
        requests.get("https://x509-limbo.com/_api/all-results.json").json()
    )

    current_results: list[LimboResult] = []
    for result in args.current.glob("*.json"):
        current_results.append(LimboResult.model_validate_json(result.read_text()))

    # mapping of harness -> [(testcase-id, previous-result, current-result)]
    regressions: dict[str, list[tuple[str, ActualResult, ActualResult]]] = defaultdict(list)
    for previous_result in previous_results:
        current_result = next(
            (r for r in current_results if r.harness == previous_result.harness), None
        )
        if not current_result:
            continue

        previous_by_id = {r.id: r for r in previous_result.results}
        current_by_id = {r.id: r for r in current_result.results}

        common_testcases = previous_by_id.keys() & current_by_id.keys()
        for tc in common_testcases:
            if previous_by_id[tc].actual_result != current_by_id[tc].actual_result:
                regressions[previous_result.harness].append(
                    (tc, previous_by_id[tc].actual_result, current_by_id[tc].actual_result)
                )

    if os.getenv("GITHUB_ACTIONS"):
        if regressions:
            _github.step_summary(_render_regressions(regressions))
            _github.comment(
                ":suspect: Regressions found. Review these changes "
                "**very carefully** before continuing!\n\n"
                f"Sampled regressions: {_github.workflow_url()}"
            )
            _github.label(add=[_github.REGRESSIONS_LABEL], remove=[_github.NO_REGRESSIONS_LABEL])
        else:
            _github.comment(":shipit: No regressions found.")
            _github.label(add=[_github.NO_REGRESSIONS_LABEL], remove=[_github.REGRESSIONS_LABEL])


def _render_regressions(
    all_regressions: dict[str, list[tuple[str, ActualResult, ActualResult]]]
) -> str:
    rendered = ""

    for harness, regressions in all_regressions.items():
        # Sample up to 10 regressions per harness.
        regressions = random.sample(regressions, min(len(regressions), 10))

        rendered += f"## {harness}\n\n"
        for tc, prev, curr in regressions:
            rendered += f"* `{tc}` went from {prev} to {curr}\n"
        rendered += "\n"

    return rendered
