#!/usr/bin/env python3
"""Extract the triage classification from docs/triage.md into triage.json.

The markdown table is the source of truth. This script makes it executable.
Run with --check in CI to fail when the two have drifted.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROW = re.compile(
    r'^\|\s*(tfsec|checkov)\s*\|\s*(\S+)\s*\|([^|]*)\|([^|]*)\|'
    r'\s*(BLOCK|WARN|IGNORE)\s*\|([^|]*)\|'
)

SRC = Path('docs/triage.md')
DST = Path('policies/opa/triage.json')


def extract():
    rules = {}
    for line in SRC.read_text().splitlines():
        m = ROW.match(line)
        if not m:
            continue
        tool, rid, sev, desc, cls, rat = m.groups()
        rules[rid] = {
            "tool": tool,
            "class": cls,
            "severity": sev.strip() or None,
            "description": desc.strip(),
            "rationale": rat.strip() or None,
        }
    return {"triage": rules}


def main():
    data = extract()
    n = len(data["triage"])
    counts = Counter(v["class"] for v in data["triage"].values())

    if n == 0:
        print("ERROR: no rules extracted — table format may have changed", file=sys.stderr)
        return 1

    rendered = json.dumps(data, indent=2, sort_keys=True) + "\n"

    if "--check" in sys.argv:
        if not DST.exists():
            print(f"ERROR: {DST} missing", file=sys.stderr)
            return 1
        if DST.read_text() != rendered:
            print(f"ERROR: {DST} is stale — run scripts/extract_triage.py", file=sys.stderr)
            return 1
        print(f"OK: {n} rules in sync {dict(counts)}")
        return 0

    DST.write_text(rendered)
    print(f"Wrote {n} rules to {DST} {dict(counts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
