"""CLI entrypoint for the Fracture scanner.

Usage: python main.py --target brokencheckout --output ./output
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import structlog

from core.runner import run_scan


def _configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )


def main() -> int:
    _configure_logging()
    parser = argparse.ArgumentParser(
        prog="fracture",
        description="Fracture - payment API security scanner.",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target config name (matches scanner/config/targets/<name>.yaml)",
    )
    parser.add_argument(
        "--output",
        default="./output",
        help="Directory to write JSONL + HTML reports to",
    )
    parser.add_argument(
        "--config-dir",
        default="config/targets",
        help="Directory containing target YAML configs",
    )
    args = parser.parse_args()

    config_path = Path(args.config_dir) / f"{args.target}.yaml"
    if not config_path.exists():
        print(f"error: target config not found at {config_path}", file=sys.stderr)
        return 2

    asyncio.run(run_scan(config_path, Path(args.output)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
