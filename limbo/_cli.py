import argparse
import contextlib
import logging
import os
import sys
from pathlib import Path
from typing import NoReturn

from limbo import testcases

from . import __version__
from .models import Limbo

logging.basicConfig()
logger = logging.getLogger(__name__)

# NOTE: We configure the top package logger, rather than the root logger,
# to avoid overly verbose logging in third-party code by default.
package_logger = logging.getLogger("limbo")
package_logger.setLevel(os.environ.get("LIMBO_LOGLEVEL", "INFO").upper())


def _die(msg: str) -> NoReturn:
    logger.error(msg)
    sys.exit(1)


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

    # `limbo compile`
    compile = subparsers.add_parser(
        "compile", help="Generate all testcases and produce a single JSON test suite"
    )
    compile.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="The path to write the testcase suite to"
    )
    compile.add_argument("-f", "--force", action="store_true", help="Overwrite any existing output")
    compile.set_defaults(func=_compile)

    args = parser.parse_args()
    args.func(args)


def _schema(args: argparse.Namespace) -> None:
    io = args.output.open(mode="w") if args.output else sys.stdout

    with contextlib.closing(io):
        print(Limbo.schema_json(indent=2), file=io)


def _compile(args: argparse.Namespace) -> None:
    all_testcases = [testcase() for _, testcase in testcases.registry.items()]
    combined = Limbo(version=1, testcases=all_testcases)

    io = args.output.open(mode="w") if args.output else sys.stdout
    with contextlib.closing(io):
        print(combined.json(indent=2), file=io)
