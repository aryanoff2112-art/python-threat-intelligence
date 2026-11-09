"""Verify a downloaded dataset against an .md5 file (GNU `md5sum` or BSD `MD5 (file) = hash` format).

    python scripts/verify_checksums.py GeneratedLabelledFlows.md5 --dir data/raw

Exit code 0 only if every listed file exists and matches. A mismatch means a corrupted or incomplete
download (or a different release); do not trust results computed from it.
MD5 detects accidental corruption only; it is not a defence against tampering.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

GNU = re.compile(r"^([0-9a-fA-F]{32})\s+\*?(.+)$")
BSD = re.compile(r"^MD5 \((.+)\) = ([0-9a-fA-F]{32})$")


def parse_md5_file(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if m := GNU.match(line):
            out.append((m.group(2).strip(), m.group(1).lower()))
        elif m := BSD.match(line):
            out.append((m.group(1), m.group(2).lower()))
        else:
            raise ValueError(f"Unrecognised checksum line: {line[:80]!r}")
    if not out:
        raise ValueError("No checksums found in file")
    return out


def md5_of(path: Path) -> str:
    h = hashlib.md5()           # integrity check only, not a security control
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(md5_file: Path, directory: Path) -> dict[str, str]:
    results = {}
    for name, expected in parse_md5_file(md5_file.read_text()):
        target = directory / Path(name).name
        if not target.exists():
            results[name] = "MISSING"
        else:
            results[name] = "OK" if md5_of(target) == expected else "MISMATCH"
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("md5_file", type=Path); ap.add_argument("--dir", type=Path, default=Path("data/raw"))
    args = ap.parse_args(argv)
    try:
        results = verify(args.md5_file, args.dir)
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}"); return 2
    for name, status in results.items():
        print(f"{status:9s} {name}")
    return 0 if all(v == "OK" for v in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
