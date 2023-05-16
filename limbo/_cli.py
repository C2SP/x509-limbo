import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .assets import assets
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
    schema.set_defaults(func=_schema)

    # `limbo build-assets`
    build_assets = subparsers.add_parser("build-assets", help="Generate and dump testcase assets")
    build_assets.add_argument(
        "-o", "--output-dir", type=Path, help="The path to write assets to", required=True
    )
    build_assets.add_argument(
        "-f", "--force", action="store_true", help="Overwrite existing assets"
    )
    build_assets.set_defaults(func=_build_assets)

    args = parser.parse_args()
    args.func(args)


def _schema(args: argparse.Namespace) -> None:
    print(Limbo.schema_json(indent=2))


def _build_assets(args: argparse.Namespace) -> None:
    print("[+] Generating assets...", file=sys.stderr)

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    for asset in assets(load_from=output_dir):
        print(f"[+]\t{asset.name}", file=sys.stderr)
        path: Path = output_dir / asset.name

        if path.exists() and not args.force:
            print(f"[!]\tNot overwriting {asset.name} without --force", file=sys.stderr)
            continue

        path.write_bytes(asset.contents)
