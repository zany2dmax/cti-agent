#!/usr/bin/env python3
"""Report #nosec annotations that suppress nothing.

Usage: nosec-audit.py <gosec-json-report>

The report must have been produced with the annotations IGNORED:

    gosec -nosec=true -fmt=json -out report.json ./...

WHY THIS EXISTS

gosec reported "Nosec: 10, Issues: 1", and two readings were equally
consistent with that line: ten real suppressions, or one real one and nine
comments justifying a finding that never fires. Running it with -nosec=true
settled it - four of the ten earned their place. The six sitting on
os.WriteFile/os.OpenFile calls suppressed nothing, because G304 fires on reads
and not on writes.

An annotation in that second category is worse than no annotation. It reads as
a considered exception, and it pins a rule ID that will not cover whatever rule
eventually does fire on that line - which is exactly how a G703 slipped past a
"#nosec G304" on the one line where it mattered.

Exits non-zero when any annotation is dead, so it can gate if you want it to.
It is advisory by default: see `task gosec:audit`.
"""

import json
import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2

    findings = set()
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    for iss in data.get("Issues") or []:
        f = str(pathlib.Path(iss["file"]).resolve())
        # "line" is sometimes a range like "261-263"; the first number is the
        # statement gosec is pointing at.
        nums = re.findall(r"\d+", str(iss["line"]))
        if nums:
            findings.add((f, int(nums[0])))

    annotated, dead = [], []
    for src in sorted(pathlib.Path(".").rglob("*.go")):
        if "/vendor/" in str(src):
            continue
        lines = src.read_text(encoding="utf-8").split("\n")
        for i, line in enumerate(lines):
            if "#nosec" not in line:
                continue
            m = re.search(r"#nosec\s+([G0-9,]+)", line)
            rules = m.group(1) if m else "(NO RULE ID)"
            # An annotation applies to the next line that is neither blank nor
            # a comment - the statement being excused.
            j = i + 1
            while j < len(lines) and (
                not lines[j].strip() or lines[j].lstrip().startswith("//")
            ):
                j += 1
            live = (str(src.resolve()), j + 1) in findings
            annotated.append((src, i + 1, rules, j + 1, live))
            if not live:
                dead.append((src, i + 1, rules, j + 1))

    print(f"  {len(annotated)} annotation(s); gosec flags "
          f"{len(findings)} line(s) with them ignored")
    for src, at, rules, tgt, live in annotated:
        print(f"    {'ok' if live else 'SUPPRESSES NOTHING':18} "
              f"{src}:{at}  #nosec {rules}  -> line {tgt}")

    if dead:
        print(f"\n  {len(dead)} annotation(s) suppress nothing. Remove the "
              f"#nosec directive and keep the prose - the explanation of why "
              f"the path is a variable is still worth reading:")
        for src, at, rules, tgt in dead:
            print(f"    {src}:{at}  (#nosec {rules})")
        return 1

    print("\n  every annotation suppresses a real finding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
