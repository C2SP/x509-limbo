import argparse

from . import __version__
from .models import Limbo


def main():
    parser = argparse.ArgumentParser(description="A self-management tool for x509-limbo")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(required=True)

    schema = subparsers.add_parser("schema", help="Dump the top-level JSON Schema for x509-limbo")
    schema.set_defaults(func=_schema)

    args = parser.parse_args()
    args.func(args)


def _schema(args: argparse.Namespace):
    print(Limbo.schema_json(indent=2))
