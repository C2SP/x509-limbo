# x509-limbo

⚠️ This is a work in progress! ⚠️

A suite of testvectors (and associated tooling) for X.509 certificate path
validation.

## How to use this repository

This repository contains canned testcases for developing or testing
implementations of X.509 path validation.

To use it, you'll need to understand (and use) three pieces:

1. [`limbo-schema.json`](./limbo-schema.json): The testcase schema. This is
   provided as a [JSON Schema](https://json-schema.org/) definition.
2. [`testcases/limbo.json`](./testcases/limbo.json): The combined testcase
   suite. The structure of this file conforms to the schema above.
3. [`testcases/assets`](./testcases/assets/): The test assets (keys, X.509
   certificates, etc.) used by individual testcases.

The schema will tell you how to consume the combined testcase suite.

## Developing

This repository contains a self-managing tool called `limbo`.

```bash
make dev && source env/bin/activate

limbo --help
```

This tool can be used to regenerate the schema, as well as
develop and manage testcases and testcase assets:

```bash
limbo schema --help
limbo build-assets --help
limbo compile --help
```

There are also two convenience `make` targets for quickly regenerating
the schema and testcases:

```bash
# regenerates `limbo-schema.json`
make schema

# regenerates `testcases/limbo.json`
make testcases
```
