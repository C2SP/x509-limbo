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

from limbo import _github, _markdown, testcases
from limbo.testcases import bettertls, online

from . import __version__
from .models import (
    ActualResult,
    Limbo,
    LimboResult,
    NewTestcaseEntry,
    RegressionData,
    RegressionEntry,
)

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
    harness.add_argument("harness", help="The harness to execute", nargs="+")
    harness.set_defaults(func=_harness)

    # `limbo regression`
    regression = subparsers.add_parser(
        "regression", help="Run regression checks against the last result set"
    )
    regression.add_argument(
        "--limbo",
        type=Path,
        default=Path("limbo.json"),
        metavar="FILE",
        help="The limbo testcase suite to load from",
    )
    regression.add_argument(
        "--current",
        type=Path,
        default=Path("results"),
        metavar="DIR",
        help="The current results to check against",
    )
    regression.add_argument(
        "--detect-only",
        action="store_true",
        help="Only detect regressions, save to --output without posting comments",
    )
    regression.add_argument(
        "--post-only",
        action="store_true",
        help="Only post comments from pre-computed regression data in --input",
    )
    regression.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="Output file for regression data (used with --detect-only)",
    )
    regression.add_argument(
        "-i",
        "--input",
        type=Path,
        metavar="FILE",
        help="Input file with regression data (used with --post-only)",
    )
    regression.set_defaults(func=_regression)

    # `limbo extract`
    extract = subparsers.add_parser("extract", help="Extract a single testcase from the test-suite")
    extract.add_argument(
        "--limbo",
        type=Path,
        default=Path("limbo.json"),
        metavar="FILE",
        help="The limbo testcase suite to load from",
    )
    extract.add_argument(
        "--output",
        type=str,
        metavar="FILE",
        help=(
            "The filename to write the extracted testcase to. "
            "By default, {id}.json will be written; use - for stdout"
        ),
    )
    extract.add_argument(
        "id", type=str, metavar="TESTCASE-ID", help="The testcase to extract, by ID"
    )
    extract.set_defaults(func=_extract)

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
            args.harness, input=limbo_json, encoding="utf-8", capture_output=True, check=True
        )
        print(result.stderr, file=sys.stderr)
        args.output.write_text(result.stdout)
    except subprocess.CalledProcessError as e:
        print(e.stderr, file=sys.stderr)
        sys.exit(1)


def _detect_regressions(args: argparse.Namespace) -> RegressionData:
    """Detect regressions and new testcases, returning structured data."""
    previous_results = TypeAdapter(list[LimboResult]).validate_python(
        requests.get("https://x509-limbo.com/_api/all-results.json").json()
    )

    current_results: list[LimboResult] = []
    for result in args.current.glob("*.json"):
        current_results.append(LimboResult.model_validate_json(result.read_text()))

    # Detect regressions: harness -> list of RegressionEntry
    all_regressions: dict[str, list[RegressionEntry]] = defaultdict(list)
    for previous_result in previous_results:
        current_result = next(
            (r for r in current_results if r.harness == previous_result.harness), None
        )
        if not current_result:
            continue

        previous_by_id = previous_result.by_id
        current_by_id = current_result.by_id

        common_testcases = previous_by_id.keys() & current_by_id.keys()
        for tc in common_testcases:
            prev_actual = previous_by_id[tc].actual_result
            curr_actual = current_by_id[tc].actual_result
            if prev_actual != curr_actual:
                all_regressions[previous_result.harness].append(
                    RegressionEntry(
                        testcase_id=tc,
                        previous_result=prev_actual.value,
                        current_result=curr_actual.value,
                    )
                )

    # Detect new testcases: harness -> list of NewTestcaseEntry
    limbo = Limbo.model_validate_json(args.limbo.read_text())
    # Assumption: all previous results have the same set of testcase IDs
    previous_tc_ids = {r.id for r in previous_results[0].results}
    new_testcases: dict[str, list[NewTestcaseEntry]] = defaultdict(list)
    for current_result in current_results:
        new_tc_ids = current_result.by_id.keys() - previous_tc_ids
        for new_tc_id in new_tc_ids:
            actual_result = current_result.by_id[new_tc_id].actual_result.value
            context = current_result.by_id[new_tc_id].context
            expected_result = limbo.by_id[new_tc_id].expected_result.value

            new_testcases[current_result.harness].append(
                NewTestcaseEntry(
                    testcase_id=new_tc_id,
                    expected_result=expected_result,
                    actual_result=actual_result,
                    context=context,
                )
            )

    # Get PR number from GitHub event
    pr_number: int | None = None
    if os.getenv("GITHUB_ACTIONS"):
        event = _github.github_event()
        pr_number = event.get("number")

    return RegressionData(
        regressions=dict(all_regressions),
        new_testcases=dict(new_testcases),
        workflow_url=_github.workflow_url() if os.getenv("GITHUB_ACTIONS") else "",
        pr_number=pr_number,
    )


def _post_regressions(data: RegressionData) -> None:
    """Post regression comments and labels based on pre-computed data."""
    if not os.getenv("GITHUB_ACTIONS"):
        logger.warning("Not running in GitHub Actions, skipping comment/label posting")
        return

    if data.regressions:
        template = _markdown.template("regressions.md")
        _github.comment(
            template.render(regressions_url=data.workflow_url), update="@@regressions@@"
        )
        _github.label(add=[_github.REGRESSIONS_LABEL], remove=[_github.NO_REGRESSIONS_LABEL])
    else:
        # Avoid spamming the user with "no regression" comments.
        if not _github.has_label(_github.NO_REGRESSIONS_LABEL):
            _github.comment(":shipit: No regressions found.", update="@@regressions@@")
            _github.label(add=[_github.NO_REGRESSIONS_LABEL], remove=[_github.REGRESSIONS_LABEL])

    if data.new_testcases:
        # Convert to tuple format for template
        new_results: dict[str, list[tuple[str, str, str, str | None]]] = {}
        for harness, entries in data.new_testcases.items():
            new_results[harness] = [
                (e.testcase_id, e.expected_result, e.actual_result, e.context) for e in entries
            ]
        template = _markdown.template("new-testcases.md")
        _github.comment(template.render(new_results=new_results), update="@@new-testcases@@")


def _regression(args: argparse.Namespace) -> None:
    """Run regression checks against the last result set."""
    if args.detect_only and args.post_only:
        logger.error("Cannot use both --detect-only and --post-only")
        sys.exit(1)

    if args.detect_only:
        if not args.output:
            logger.error("--detect-only requires --output")
            sys.exit(1)

        data = _detect_regressions(args)
        args.output.write_text(data.model_dump_json(indent=2))

        # Still write to step summary for visibility in first workflow
        if os.getenv("GITHUB_ACTIONS"):
            summary_parts = []

            if data.regressions:
                all_regressions: dict[str, list[tuple[str, ActualResult, ActualResult]]] = {}
                for harness, entries in data.regressions.items():
                    all_regressions[harness] = [
                        (
                            e.testcase_id,
                            ActualResult(e.previous_result),
                            ActualResult(e.current_result),
                        )
                        for e in entries
                    ]
                sampled = _sample_regressions(all_regressions)
                template = _markdown.template("sampled-regressions.md")
                summary_parts.append(
                    template.render(
                        sampled_regressions=sampled, testcase_link=_markdown.testcase_link
                    )
                )

            if data.new_testcases:
                new_results: dict[str, list[tuple[str, str, str, str | None]]] = {}
                for harness, new_entries in data.new_testcases.items():
                    new_results[harness] = [
                        (e.testcase_id, e.expected_result, e.actual_result, e.context)
                        for e in new_entries
                    ]
                template = _markdown.template("new-testcases.md")
                summary_parts.append(template.render(new_results=new_results))

            if summary_parts:
                _github.step_summary("\n\n".join(summary_parts))

        logger.info(f"Regression data saved to {args.output}")
        return

    if args.post_only:
        if not args.input:
            logger.error("--post-only requires --input")
            sys.exit(1)

        data = RegressionData.model_validate_json(args.input.read_text())

        if data.pr_number is None:
            logger.error(
                "regression data is missing pr_number - was it generated outside GitHub Actions?"
            )
            sys.exit(1)

        # Set PR number override for _github module
        os.environ["LIMBO_PR_NUMBER"] = str(data.pr_number)

        _post_regressions(data)
        return

    # Legacy mode: detect and post in one go (for local testing or same-repo PRs)
    data = _detect_regressions(args)
    _post_regressions(data)


def _sample_regressions(
    all_regressions: dict[str, list[tuple[str, ActualResult, ActualResult]]],
) -> dict[str, list[tuple[str, ActualResult, ActualResult]]]:
    sampled = {}
    for harness, regressions in all_regressions.items():
        # Sample up to 10 regressions per harness.
        # Filter the bettertls suite by default, since it's huge.
        # But re-include if we can't sample enough.
        regressions_without_bettertls = [
            r for r in regressions if not r[0].startswith("bettertls::")
        ]
        if len(regressions_without_bettertls) >= 10:
            regressions = random.sample(regressions_without_bettertls, 10)
        else:
            regressions = random.sample(regressions, min(len(regressions), 10))

        sampled[harness] = regressions

    return sampled


def _extract(args: argparse.Namespace) -> None:
    limbo = Limbo.model_validate_json(args.limbo.read_text())

    try:
        testcase = limbo.by_id[args.id]
    except KeyError:
        logger.error(f"no such testcase: {args.id}")
        sys.exit(1)

    output = args.output
    if not output:
        output = f"{args.id}.json"

    if args.output == "-":
        print(testcase.model_dump_json(indent=2), file=sys.stdout)
    else:
        Path(output).write_text(testcase.model_dump_json(indent=2))
