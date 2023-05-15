# x509-limbo

⚠️ This is a work in progress! ⚠️

A suite of testvectors (and associated tooling) for X.509 certificate path
validation.

## Developing

This repository contains a self-managing tool called `limbo`.

```bash
python -m venv env && source env/bin/activate
python -m pip install -e .[dev]

limbo --help
```
