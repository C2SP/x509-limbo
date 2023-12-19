#!/usr/bin/env python

# render-testcases: convert `limbo.json` into pretty pages
# TODO(ww): Use some kind of Markdown builder API here, rather than
# smashing strings together.

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import mkdocs_gen_files
from json_schema_for_humans.generate import generate_from_file_object
from json_schema_for_humans.generation_configuration import GenerationConfiguration
from py_markdown_table.markdown_table import markdown_table

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

LIMBO_SCHEMA_JSON = _HERE.parent / "limbo-schema.json"
assert LIMBO_SCHEMA_JSON.is_file()

RESULTS = _HERE.parent / "results"

BASE_URL = "https://trailofbits.github.io/x509-limbo"

TESTCASE_TEMPLATE = """
## {tc_id}

{description}

| Expected result | Validation kind | Validation time | Features   | Conflicts   | Download |
| --------------- | --------------- | --------------- | ---------- | ----------- | -------- |
| {exp_result}    | {val_kind}      | {val_time}      | {features} | {conflicts} | {pems}   |

{harness_results}
"""


LINK_SUBSTITUTIONS = [
    # Rewrite `RFC XXXX A.B.C.D` into a section link.
    (
        r"(?<!\[)RFC (\d+) (\d(?:.\d)*)(?!\])",
        r"[\g<0>](https://datatracker.ietf.org/doc/html/rfc\g<1>#section-\g<2>)",
    ),
    # Rewrite bare `RFC XXXX` into an RFC link.
    (
        r"(?<!\[)RFC (\d+)(?!\])",
        r"[\g<0>](https://datatracker.ietf.org/doc/html/rfc\g<1>)",
    ),
    # Rewrite `CABF` into a PDF link.
    # TODO(ww): Figure out a good way to hotlink to specific CABF sections.
    (
        r"(?<!\[)CABF(?!\])",
        r"[\g<0>](https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.1.pdf)",
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


def _testcase_url(testcase_id: TestCaseID) -> str:
    namespace, _ = testcase_id.split("::", 1)
    slug = testcase_id.replace("::", "")
    return f"{BASE_URL}/testcases/{namespace}/#{slug}"


def _render_conflicts(tc: Testcase) -> str:
    if not tc.conflicts_with:
        return "N/A"

    urls = [_testcase_url(id_) for id_ in tc.conflicts_with]
    md_urls = [f"[`{id_}`]({url})" for (id_, url) in zip(tc.conflicts_with, urls)]

    return ", ".join(md_urls)


def _tc_pem_bundle(tc: Testcase) -> str:
    # NOTE: Don't bother generating or linking individual PEMs for
    # the bettertls suite, since they're entirely auto-generated.
    if tc.id.startswith("bettertls"):
        return ""

    namespace, _ = tc.id.split("::", 1)
    slug = tc.id.replace("::", "")

    bundle = [tc.peer_certificate, *tc.untrusted_intermediates, *tc.trusted_certs]
    with mkdocs_gen_files.open(f"testcases/{namespace}/assets/{slug}/bundle.pem", "w") as f:
        print("\n".join(bundle), file=f)

    return f"[PEM bundle]({BASE_URL}/testcases/{namespace}/assets/{slug}/bundle.pem)"


def _result_emoji(expected: ExpectedResult, actual: ActualResult):
    match expected.value, actual.value:
        case ("SUCCESS", "SUCCESS") | ("FAILURE", "FAILURE"):
            return "✅"
        case (_, "SKIPPED"):
            return "🚧"
        case _:
            return f"❌ (unexpected {actual.value.lower()})"


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
                "Context": f"`{tc_result.context}`" if tc_result.context else "N/A",
            }
        )
    return markdown_table(data).set_params(quote=False, row_sep="markdown").get_markdown()


limbo = Limbo.model_validate_json(LIMBO_JSON.read_text())
if RESULTS.is_dir():
    limbo_results = [LimboResult.model_validate_json(f.read_text()) for f in RESULTS.glob("*.json")]
else:
    limbo_results = []


# Mapping: tc_id -> [(harness_id, result)]
results_by_tc_id: dict[TestCaseID, list[tuple[str, TestcaseResult]]] = defaultdict(list)
for limbo_result in limbo_results:
    for result in limbo_result.results:
        results_by_tc_id[result.id].append((limbo_result.harness, result))


namespaces: dict[str, list[CollatedResult]] = defaultdict(list)
for tc in limbo.testcases:
    namespace, _ = tc.id.split("::", 1)

    collated = CollatedResult(tc=tc, results=results_by_tc_id[tc.id])
    namespaces[namespace].append(collated)

for namespace, results in namespaces.items():
    with mkdocs_gen_files.open(f"testcases/{namespace}.md", "w") as f:
        print(f"# {namespace}", file=f)

        for r in results:
            print(
                TESTCASE_TEMPLATE.format(
                    tc_id=r.tc.id,
                    exp_result=r.tc.expected_result.value,
                    val_kind=r.tc.validation_kind.value,
                    val_time=r.tc.validation_time.isoformat() if r.tc.validation_time else "N/A",
                    features=", ".join([f.value for f in r.tc.features])
                    if r.tc.features
                    else "N/A",
                    description=_linkify(r.tc.description.strip()),
                    conflicts=_render_conflicts(r.tc),
                    pems=_tc_pem_bundle(r.tc),
                    harness_results=_render_harness_results(r.results, r.tc.expected_result),
                ),
                file=f,
            )

with mkdocs_gen_files.open("schema.md", "w") as f, NamedTemporaryFile(mode="w+") as schema:
    print(json.dumps(Limbo.model_json_schema()), file=schema)
    schema.seek(0)
    generate_from_file_object(
        schema,
        f,
        config=GenerationConfiguration(
            template_name="md",
            show_toc=False,
        ),
    )
