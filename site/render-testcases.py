#!/usr/bin/env python

# render-testcases: convert `limbo.json` into pretty pages
# TODO(ww): Use some kind of Markdown builder API here, rather than
# smashing strings together.

import re
from collections import defaultdict
from pathlib import Path

import mkdocs_gen_files

from limbo.models import Limbo, Testcase, TestCaseID

LIMBO_JSON = Path(__file__).parent.parent / "limbo.json"
assert LIMBO_JSON.is_file()

TESTCASE_TEMPLATE = """
## {tc_id}

{description}

{conflicts}

| Expected result | Validation kind | Validation time | Features   |
| --------------- | --------------- | --------------- | ---------- |
| {exp_result}    | {val_kind}      | {val_time}      | {features} |
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


def _linkify(description: str) -> str:
    for pat, subst in LINK_SUBSTITUTIONS:
        description = re.sub(pat, subst, description)
    return description


def _testcase_url(testcase_id: TestCaseID) -> str:
    namespace, _ = testcase_id.split("::", 1)
    slug = testcase_id.replace("::", "")
    return f"https://trailofbits.github.io/x509-limbo/testcases/{namespace}/#{slug}"


def _render_conflicts(tc: Testcase) -> str:
    if not tc.conflicts_with:
        return ""

    urls = [_testcase_url(id_) for id_ in tc.conflicts_with]
    md_urls = [f"[`{id_}`]({url})" for (id_, url) in zip(tc.conflicts_with, urls)]

    return ", ".join(md_urls)


limbo = Limbo.parse_file(LIMBO_JSON)

namespaces: dict[str, list[Testcase]] = defaultdict(list)
for tc in limbo.testcases:
    namespace, _ = tc.id.split("::", 1)
    namespaces[namespace].append(tc)

for namespace, tcs in namespaces.items():
    with mkdocs_gen_files.open(f"testcases/{namespace}.md", "w") as f:
        print(f"# {namespace}", file=f)

        for tc in tcs:
            print(
                TESTCASE_TEMPLATE.format(
                    tc_id=tc.id,
                    exp_result=tc.expected_result.value,
                    val_kind=tc.validation_kind.value,
                    val_time=tc.validation_time.isoformat() if tc.validation_time else "N/A",
                    features=", ".join([f.value for f in tc.features]) if tc.features else "N/A",
                    description=_linkify(tc.description.strip()),
                    conflicts=_render_conflicts(tc),
                ),
                file=f,
            )
