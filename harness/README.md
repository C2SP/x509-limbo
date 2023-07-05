# Test harnesses for x509-limbo

This directory contains example test harness for x509-limbo.

These are not "upstream" harnesses; they exist primarily to help with
x509-limbo's own development.

## Harness behavior

Each harness should behave as follows:

1. It should be a single binary that takes no inputs or flags;
1. It should load the current Limbo testcase set
   (i.e., [../limbo.json](../limbo.json));
1. It should exit with a non-zero exit code on any harness-specific
   errors (i.e. failure to parse a testcase, unexpected internal errors);
1. On success (all testcases evaluated) it should produce a `results.json`
   output in its harness directory. This file should match the
   `LimboResult` schema, which is internal to this repository.
