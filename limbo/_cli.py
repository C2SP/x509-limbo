import argparse
import contextlib
import json
import logging
import os
import sys
from pathlib import Path

from pydantic.schema import schema

from limbo import testcases
from limbo.testcases.webpki import online

from . import __version__
from .models import Limbo

logging.basicConfig()
logger = logging.getLogger(__name__)

# NOTE: We configure the top package logger, rather than the root logger,
# to avoid overly verbose logging in third-party code by default.
package_logger = logging.getLogger("limbo")
package_logger.setLevel(os.environ.get("LIMBO_LOGLEVEL", "INFO").upper())


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

    # `limbo online-cases`
    online_cases = subparsers.add_parser(
        "online-cases", help="Regenerate cached testcases made from online requests"
    )
    online_cases.set_defaults(func=_online_cases)

    # `limbo compile`
    compile = subparsers.add_parser(
        "compile", help="Generate all testcases and produce a single JSON test suite"
    )
    compile.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="The path to write the testcase suite to"
    )
    compile.add_argument("--online", action="store_true", help="Regenerate cached online testcases")
    compile.add_argument("-f", "--force", action="store_true", help="Overwrite any existing output")
    compile.set_defaults(func=_compile)

    # `limbo dump-chain`
    dump_chain = subparsers.add_parser(
        "dump-chain", help="Dump each PEM-formatted certificate in a given testcase"
    )
    dump_chain.add_argument(
        "input", type=Path, metavar="FILE", help="The limbo testcase suite to load from"
    )
    dump_chain.add_argument("id", type=str, metavar="ID", help="The testcase ID to dump")
    dump_chain.set_defaults(func=_dump_chain)

    args = parser.parse_args()
    args.func(args)


def _schema(args: argparse.Namespace) -> None:
    io = args.output.open(mode="w") if args.output else sys.stdout

    with contextlib.closing(io):
        top = schema([Limbo], title="x509-limbo schemas")
        print(json.dumps(top, indent=2), file=io)


def _online_cases(args: argparse.Namespace) -> None:
    online.compile()


def _compile(args: argparse.Namespace) -> None:
    if args.online:
        online.compile()

    online.register_testcases()
    all_testcases = [testcase() for _, testcase in testcases.registry.items()]
    combined = Limbo(version=1, testcases=all_testcases)

    io = args.output.open(mode="w") if args.output else sys.stdout
    with contextlib.closing(io):
        print(combined.json(indent=2), file=io)


def _dump_chain(args: argparse.Namespace) -> None:
    limbo = Limbo.parse_file(args.input)
    testcase = next(tc for tc in limbo.testcases if tc.id == args.id)

    # Dump EE first, then intermediates, then trusted certs.
    print(testcase.peer_certificate)
    for cert in testcase.untrusted_intermediates:
        print(cert)
    for cert in testcase.trusted_certs:
        print(cert)
