#!/usr/bin/env python

# render-testcases: convert `limbo.json` into a pretty page

from collections import defaultdict
from pathlib import Path

import mkdocs_gen_files

from limbo.models import Limbo, Testcase

LIMBO_JSON = Path(__file__).parent.parent / "limbo.json"
assert LIMBO_JSON.is_file()

limbo = Limbo.parse_file(LIMBO_JSON)

groups: dict[str, list[Testcase]] = defaultdict(list)
for tc in limbo.testcases:
    group, _ = tc.id.split("::", 1)
    groups[group].append(tc)

for group, tcs in groups.items():
    with mkdocs_gen_files.open(f"testcases/{group}.md", "w") as f:
        print(f"# {group}", file=f)

        for tc in tcs:
            print(f"## `{tc.id}`", file=f)

            print(tc.description, file=f)
