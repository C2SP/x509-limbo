#!/usr/bin/env python

# render-testcases: convert `limbo.json` into pretty pages
# TODO(ww): Use some kind of Markdown builder API here, rather than
# smashing strings together.

from collections import defaultdict
from pathlib import Path

import mkdocs_gen_files

from limbo.models import Limbo, Testcase

LIMBO_JSON = Path(__file__).parent.parent / "limbo.json"
assert LIMBO_JSON.is_file()

TESTCASE_TEMPLATE = """
## {tc_id}

{description}

| Expected result | Validation kind | Validation time | Features   |
| --------------- | --------------- | --------------- | ---------- |
| {exp_result}    | {val_kind}      | {val_time}      | {features} |
"""

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
                    description=tc.description,
                ),
                file=f,
            )
