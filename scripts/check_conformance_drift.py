"""Conformance drift check: the kit and the implementation must ship one spec.

``conformance/verify_vectors.py`` and ``conformance/vectors/`` are the *same
specification* in two repositories: the helper repo uses them to prove its own
code, and this kit hands them to strangers who have no access to that code. The
moment the two copies differ, "passes in the kit" stops meaning "matches the
implementation", so this script compares them file by file and exits 1 on any
difference.

Two trees are deliberately excluded, and the exclusion is printed rather than
silent, because a drift check that quietly skips things is the thing it claims
to check:

* ``conformance/benchmarks/receipts/`` — a receipt records one run on one host
  with that host's signing key. The kit publishes its own copies; making them
  equal to a laptop's latest run would mean re-signing evidence, which is not
  what a specification mirror is for.
* ``conformance/benchmarks/*.submission`` and ``__pycache__`` — inputs and
  build artefacts that belong to the implementation repo only.

Run::

    python scripts/check_conformance_drift.py --helper ../helper

Exit codes: 0 no drift, 1 drift or the helper checkout is missing, 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

KIT_ROOT = Path(__file__).resolve().parent.parent
#: Where the kit's mirror of the specification lives, inside each repo.
SPEC_SUBPATH = "conformance"
#: Paths (relative to the repo) that are not part of the mirrored spec.
EXCLUDED_PREFIXES = (
    "conformance/benchmarks/receipts",
    "conformance/__pycache__",
)
EXCLUDED_SUFFIXES = (".submission",)

#: Why each exclusion exists. Printed on every run: the exclusions are a claim.
EXCLUDED_REASON = {
    "conformance/benchmarks/receipts": (
        "per-run, per-host signed evidence; the kit publishes its own copies"
    ),
    "conformance/__pycache__": "byte-code, not a specification",
    ".submission": "benchmark input generated in the implementation repo",
}


def _is_excluded(relative: str) -> bool:
    if any(relative == p or relative.startswith(p + "/") for p in EXCLUDED_PREFIXES):
        return True
    return any(relative.endswith(suffix) for suffix in EXCLUDED_SUFFIXES)


def digest_tree(root: Path) -> dict[str, str]:
    """Every specification file under ``root/conformance`` as path -> SHA-256."""
    spec = root / SPEC_SUBPATH
    if not spec.is_dir():
        raise NotADirectoryError(f"{spec} does not exist")
    out: dict[str, str] = {}
    for path in sorted(spec.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _is_excluded(relative):
            continue
        out[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _helper_head(helper: Path) -> str:
    """The helper commit the kit is mirrored against, or ``unknown``."""
    try:
        done = subprocess.run(  # noqa: S603 - git rev-parse on a checkout we were given
            ["git", "-C", str(helper), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return done.stdout.strip() or "unknown"


def _source_commit() -> str:
    path = KIT_ROOT / "SOURCE_COMMIT"
    if not path.exists():
        return "missing"
    return path.read_text(encoding="utf-8").strip() or "empty"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--helper",
        default=os.environ.get("ASL_HELPER_ROOT", "../helper"),
        help="path to a checkout of the ASL implementation repository",
    )
    parser.add_argument(
        "--require-source-commit",
        action="store_true",
        help="also fail when SOURCE_COMMIT does not name the helper checkout's HEAD",
    )
    args = parser.parse_args(argv)

    helper = Path(args.helper).resolve()
    if not (helper / SPEC_SUBPATH).is_dir():
        print(f"DRIFT: no {SPEC_SUBPATH}/ directory at the helper checkout {helper}")
        print("       pass --helper PATH (or set ASL_HELPER_ROOT) to a real checkout")
        return 1

    kit = digest_tree(KIT_ROOT)
    other = digest_tree(helper)
    only_kit = sorted(set(kit) - set(other))
    only_helper = sorted(set(other) - set(kit))
    differs = sorted(name for name in set(kit) & set(other) if kit[name] != other[name])

    print(f"compared {len(set(kit) & set(other))} specification files")
    for prefix, reason in EXCLUDED_REASON.items():
        print(f"excluded from the comparison: {prefix} - {reason}")

    for name in only_kit:
        print(f"DRIFT only-in-kit:    {name}")
    for name in only_helper:
        print(f"DRIFT only-in-helper: {name}")
    for name in differs:
        print(f"DRIFT differs:        {name} kit={kit[name][:16]} helper={other[name][:16]}")

    # Provenance is reported always and gated only when asked for: the file
    # trees are the invariant, while the commit id moves every time the
    # implementation repo commits something that does not touch conformance/.
    source_commit = _source_commit()
    head = _helper_head(helper)
    print(f"kit SOURCE_COMMIT: {source_commit}")
    print(f"helper HEAD:       {head}")
    if source_commit != head:
        print("NOTE: SOURCE_COMMIT does not name the helper checkout's HEAD")
    if args.require_source_commit and source_commit != head:
        print("DRIFT: SOURCE_COMMIT is stale and --require-source-commit was given")
        return 1

    if only_kit or only_helper or differs:
        print(
            f"drift: {len(only_kit)} only-in-kit, {len(only_helper)} only-in-helper, "
            f"{len(differs)} differing"
        )
        return 1
    print("no conformance drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
