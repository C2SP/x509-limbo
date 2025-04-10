#!/usr/bin/env python

# render-testcases: convert `limbo.json` into pretty pages
# TODO(ww): Use some kind of Markdown builder API here, rather than
# smashing strings together.

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import mkdocs_gen_files
from py_markdown_table.markdown_table import markdown_table

from limbo._markdown import template, testcase_link, testcase_url
from limbo.models import (
    ActualResult,
    ExpectedResult,
    Limbo,
    LimboResult,
    Testcase,
    TestCaseID,
    TestcaseResult,
)

_HERE = Path(__file__).parent

LIMBO_JSON = _HERE.parent / "limbo.json"
assert LIMBO_JSON.is_file()

RESULTS = _HERE.parent / "results"

BASE_URL = mkdocs_gen_files.config["site_url"]

LINK_SUBSTITUTIONS = [
    # Rewrite `RFC XXXX A.B.C.D` into a section link.
    (
        re.compile(r"(?<!\[)RFC (\d+) (\d+(?:.\d+)*)(?!\])"),
        r"[\g<0>](https://datatracker.ietf.org/doc/html/rfc\g<1>#section-\g<2>)",
    ),
    # Rewrite bare `RFC XXXX` into an RFC link.
    (
        re.compile(r"(?<!\[)RFC (\d+)(?!\])"),
        r"[\g<0>](https://datatracker.ietf.org/doc/html/rfc\g<1>)",
    ),
    # Rewrite `CABF` into a PDF link.
    # TODO(ww): Figure out a good way to hotlink to specific CABF sections.
    (
        re.compile(r"(?<!\[)CABF(?!\])"),
        r"[\g<0>](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.1.pdf)",
    ),
    # Rewrite `CVE-YYYY-ABCDEF` into a NIST NVD link.
    (
        re.compile(r"(?<!\[)CVE-(\d{4})-(\d+(?:.\d+)*)(?!\])"),
        r"[\g<0>](https://nvd.nist.gov/vuln/detail/CVE-\g<1>-\g<2>)",
    ),
]


@dataclass
class CollatedResult:
    tc: Testcase
    results: list[tuple[str, TestcaseResult]]


def _linkify(description: str) -> str:
    for pat, subst in LINK_SUBSTITUTIONS:
        description = re.sub(pat, subst, description)
    return description


def _render_conflicts(tc: Testcase) -> str:
    if not tc.conflicts_with:
        return "N/A"

    urls = [testcase_url(id_) for id_ in tc.conflicts_with]
    md_urls = [f"[`{id_}`]({url})" for (id_, url) in zip(tc.conflicts_with, urls)]

    return ", ".join(md_urls)


def _result_emoji(expected: ExpectedResult, actual: ActualResult):
    match expected.value, actual.value:
        case ("SUCCESS", "SUCCESS") | ("FAILURE", "FAILURE"):
            return "✅"
        case (_, "SKIPPED"):
            return "🚧"
        case _:
            return f"❌ (unexpected {actual.value.lower()})"


def _multiline_cell(cell: str) -> str:
    # Nasty hack to make multiple lines render correctly in individual table cells.
    return cell.replace("\n", "<br>")


def _render_harness_results(
    results: list[tuple[str, TestcaseResult]], expected: ExpectedResult
) -> str:
    if not results:
        return ""

    data = []
    for harness, tc_result in results:
        data.append(
            {
                "Harness": f"`{harness}`",
                "Result": _result_emoji(expected, tc_result.actual_result),
                "Context": f"{_multiline_cell(tc_result.context)}" if tc_result.context else "N/A",
            }
        )
    return markdown_table(data).set_params(quote=False, row_sep="markdown").get_markdown()


limbo = Limbo.model_validate_json(LIMBO_JSON.read_bytes())

if RESULTS.is_dir():
    harness_results = [
        LimboResult.model_validate_json(f.read_bytes()) for f in RESULTS.glob("*.json")
    ]
else:
    harness_results = []


# Mapping: tc_id -> [(harness_id, result)]
results_by_tc_id: dict[TestCaseID, list[tuple[str, TestcaseResult]]] = defaultdict(list)
for harness_result in harness_results:
    for testcase_result in harness_result.results:
        results_by_tc_id[testcase_result.id].append((harness_result.harness, testcase_result))


namespaces: dict[str, list[CollatedResult]] = defaultdict(list)
for tc in limbo.testcases:
    namespace, _ = tc.id.split("::", 1)

    collated = CollatedResult(tc=tc, results=results_by_tc_id[tc.id])
    namespaces[namespace].append(collated)

for namespace, tc_results in namespaces.items():
    with mkdocs_gen_files.open(f"testcases/{namespace}.md", "w") as f:
        print(f"# {namespace}", file=f)

        for r in tc_results:
            testcase_template = template("testcase.md")
            print(
                testcase_template.render(
                    tc_id=r.tc.id,
                    exp_result=r.tc.expected_result.value,
                    val_kind=r.tc.validation_kind.value,
                    val_time=r.tc.validation_time.isoformat() if r.tc.validation_time else "N/A",
                    features=", ".join([f.value for f in r.tc.features])
                    if r.tc.features
                    else "N/A",
                    importance=r.tc.importance.value,
                    description=_linkify(r.tc.description.strip()),
                    conflicts=_render_conflicts(r.tc),
                    harness_results=_render_harness_results(r.results, r.tc.expected_result),
                ),
                file=f,
            )


for harness_result in harness_results:
    with mkdocs_gen_files.open(f"anomalous-results/{harness_result.harness}.md", "w") as f:
        print(f"# {harness_result.harness}", file=f)

        unexpected_failures: list[TestcaseResult] = []
        unexpected_passes: list[TestcaseResult] = []
        skipped_testcases: list[TestcaseResult] = []
        for testcase_result in harness_result.results:
            try:
                # The local results might be newer than the latest test suite,
                # so skip anything that doesn't have a corresponding testcase.
                expected_result = limbo.by_id[testcase_result.id].expected_result
            except KeyError:
                continue

            match (expected_result.value, testcase_result.actual_result.value):
                case ("SUCCESS", "SUCCESS") | ("FAILURE", "FAILURE"):
                    continue
                case ("SUCCESS", "FAILURE"):
                    unexpected_failures.append(testcase_result)
                case ("FAILURE", "SUCCESS"):
                    unexpected_passes.append(testcase_result)
                case (_, "SKIPPED"):
                    skipped_testcases.append(testcase_result)

        sections: dict[str, tuple[str, list[TestcaseResult]]] = {
            "Unexpected verifications": (
                "These testcases were expected to fail, but succeeded instead.",
                unexpected_passes,
            ),
            "Unexpected failures": (
                "These testcases were expected to succeed, but failed instead.",
                unexpected_failures,
            ),
            "Skipped tests": (
                "These testcases were skipped due to a harness or implementation limitation.",
                skipped_testcases,
            ),
        }

        for header, (desc, tc_results) in sections.items():
            # No anomalous results in this section; don't bother rendering it.
            if not tc_results:
                continue

            print(f"## {header}", file=f)
            print(f"{desc}\n", file=f)

            table = [
                {
                    "Testcase": testcase_link(tc_result.id),
                    "Context": _multiline_cell(tc_result.context) if tc_result.context else "N/A",
                }
                for tc_result in tc_results
            ]
            print(
                markdown_table(table).set_params(quote=False, row_sep="markdown").get_markdown(),
                file=f,
            )
            print("\n\n", file=f)


# Create an unofficial JSON API for the latest results.
with mkdocs_gen_files.open("_api/all-results.json", "w") as f:
    result_dicts = [hr.model_dump(mode="json", by_alias=True) for hr in harness_results]
    json.dump(result_dicts, f)
