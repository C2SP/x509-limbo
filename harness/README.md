# Test harnesses for x509-limbo

This directory contains example test harness for x509-limbo.

These are not "upstream" harnesses; they exist primarily to help with
x509-limbo's own development.

## Harness behavior

Each harness should behave as follows:

1. It can be either a single binary or multiple arguments (e.g. `docker run ...`);
1. It should read a Limbo-formatted testsuite via `stdin`;
1. It should exit with a non-zero exit code on any harness-specific errors
   (e.g. unexpected internal errors, not testcase failures);
1. It *may* log informational or error messages to `stderr`;
1. It should write a JSON-formatted result summary to `stdout`. The format
   of this result payload should match the `LimboResult` schema, which
   is internal to this repository.

In other words, every harness should behave correctly if invoked like
this:

```bash
./harness < limbo.json > results.json
```
