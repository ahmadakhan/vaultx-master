#!/usr/bin/env python3
"""Permanent VaultX repo operations runner.

Replaces PowerShell-based command execution (which suffers from string
escaping issues on Windows) with Python subprocess calls that pass argv as
lists, so no shell quoting is required.

Usage:
    python scripts\\vx.py list
    python scripts\\vx.py run -- ruff check backend
    python scripts\\vx.py run-json C:\\path\\to\\cmd.json --cwd backend
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

_CYAN = "\033[96m"
_GREEN = "\033[92m"
_RED = "\033[91m"
_RESET = "\033[0m"

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".next",
    ".dist",
    "dist",
    "build",
}


def _emit(cmd: list[str], cwd: Path | None) -> None:
    safe = " ".join(f'"{c}"' if (" " in c or "\t" in c) else c for c in cmd)
    place = f" (in {cwd})" if cwd else ""
    print(f"{_CYAN}${safe}{place}{_RESET}")


def run(cmd: list[str], *, cwd: Path | None = None) -> int:
    _emit(cmd, cwd)
    proc = subprocess.run(cmd, cwd=cwd, check=False)
    return proc.returncode


def cmd_list(_: argparse.Namespace) -> int:
    files: list[Path] = []
    dirs: list[Path] = []
    for path in ROOT.rglob("*"):
        if path.name in SKIP_DIRS and path.is_dir():
            continue
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in SKIP_DIRS:
            continue
        if path.is_dir():
            dirs.append(path)
        elif path.is_file():
            files.append(path)
    files.sort()
    dirs.sort()
    print(f"{_CYAN}=== VaultX repo: {ROOT} ==={_RESET}")
    for p in files:
        print(f"  {p.relative_to(ROOT)}")
    print(f"\n{_GREEN}{len(files)} files, {len(dirs)} directories{_RESET}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cmd = args.cmd
    if not cmd:
        print(f"{_RED}No command supplied. Use: run -- <cmd> [args...]{_RESET}")
        return 2
    if cmd[0] == "--":
        cmd = cmd[1:]
    cwd = Path(args.cwd) if args.cwd else None
    return run(cmd, cwd=cwd)


def cmd_run_json(args: argparse.Namespace) -> int:
    spec = Path(args.file)
    try:
        cmd = json.loads(spec.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{_RED}Invalid command spec file {spec}: {exc}{_RESET}")
        return 2
    if not isinstance(cmd, list) or not all(isinstance(x, str) for x in cmd):
        print(f"{_RED}Command spec must be a JSON list of strings.{_RESET}")
        return 2
    cwd = Path(args.cwd) if args.cwd else None
    return run(cmd, cwd=cwd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vx",
        description="VaultX repo operations runner (PowerShell-free, escaping-free).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list repo files (excluding caches/venvs)")
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser(
        "run",
        help="run an argv list via subprocess (no shell). Put args after '--'.",
    )
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="argv to execute, e.g. -- ruff check backend")
    p_run.add_argument("--cwd", default=None, help="working directory")
    p_run.set_defaults(func=cmd_run)

    p_json = sub.add_parser(
        "run-json",
        help="run an argv list read from a JSON spec file (fully escaping-free)",
    )
    p_json.add_argument("file", help="JSON file: list of argv strings")
    p_json.add_argument("--cwd", default=None, help="working directory")
    p_json.set_defaults(func=cmd_run_json)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
