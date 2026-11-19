#!/usr/bin/env python3
"""Write the software bill of materials (CycloneDX 1.5, JSON) for this release.

Usage:
    sbom.py [--out FILE] [--version V]      write the SBOM (default dist/sbom/cti-agent-<version>.cdx.json)
    sbom.py --check                         verify the no-dependency rule; write nothing

`task sbom` runs it and `task ship` runs it, so the SBOM is made every time the
code is shipped and cannot go stale.

WHAT IT RECORDS

The fleet is a Go program and a set of bash and Python lanes, built with one
rule: no third-party code. The Go module has no dependencies (standard library
only) and the Python lanes import only the standard library. The SBOM states
that, and the script PROVES it rather than asserting it: it reads go.mod and
parses every Python file's imports, and `--check` (and the normal run) fail if
either finds something that is not the standard library. A dependency added by
accident turns the next `task ship` red, which is the push-back the rule asks
for.

  applications   each Go command under cmd/ (one component each), and the
                 bash/Python lanes as one component
  libraries      the Go standard library (the toolchain version), every module
                 in go.mod (none today), and every third-party Python import
                 (none today)
  platform       the host's python3 and bash, which the lanes need and the
                 operating system provides (no version: it is the host's)

The output is deterministic for a given commit (the serial number is derived
from the version and commit, and components are sorted), so two runs of the same
tree produce the same file apart from the timestamp.

This is build tooling for the maintainer, not a fleet feature: it uses only the
Python standard library and `go`/`git`, and it is never installed on the box.
"""
import argparse
import ast
import json
import os
import re
import subprocess  # nosec B404
import sys
import uuid
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PURL_NS = "pkg:github/zany2dmax/cti-agent"


class Rule(Exception):
    """The no-dependency rule is broken."""


def run(*cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)  # nosec B603


def git_version():
    r = run("git", "describe", "--tags", "--always", "--dirty")
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else "unknown"


def git_commit():
    r = run("git", "rev-parse", "HEAD")
    return r.stdout.strip() if r.returncode == 0 else ""


def go_toolchain():
    r = run("go", "env", "GOVERSION")
    v = r.stdout.strip()
    return v[2:] if v.startswith("go") else (v or "unknown")


def go_modules():
    """(path, version) of every module the main module requires. Parsed from
    go.mod directly: the standard library has no parser for it, and the file's
    grammar here is two forms."""
    with open(os.path.join(ROOT, "go.mod"), encoding="utf-8") as f:
        text = f.read()
    mods = []
    for block in re.findall(r"(?ms)^require\s*\((.*?)^\)", text):
        for line in block.splitlines():
            line = line.split("//")[0].strip()
            if line:
                parts = line.split()
                if len(parts) >= 2:
                    mods.append((parts[0], parts[1]))
    for line in re.findall(r"(?m)^require\s+(\S+\s+\S+)", text):
        parts = line.split()
        mods.append((parts[0], parts[1]))
    return sorted(set(mods))


def go_commands():
    base = os.path.join(ROOT, "cmd")
    return sorted(d for d in os.listdir(base)
                  if os.path.isfile(os.path.join(base, d, "main.go")))


def python_files():
    out = []
    for d in ("fleet-kit/fleet/lanes", "fleet-kit/fleet/bin", "scripts"):
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, encoding="utf-8") as f:
                    head = f.readline()
            except (OSError, UnicodeDecodeError):
                continue
            if name.endswith(".py") or ("python" in head and head.startswith("#!")):
                out.append(p)
    return out


def third_party_imports():
    """{module: [files]} for every import that is not the standard library or
    this repository's own code."""
    std = set(sys.stdlib_module_names)
    local = {os.path.splitext(os.path.basename(p))[0] for p in python_files()}
    found = {}
    for p in python_files():
        with open(p, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=p)
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names += [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.append(node.module.split(".")[0])
        for n in names:
            if n not in std and n not in local:
                found.setdefault(n, []).append(os.path.relpath(p, ROOT))
    return {k: sorted(set(v)) for k, v in sorted(found.items())}


def check():
    """Raise Rule if anything but the standard library is in use."""
    problems = []
    mods = go_modules()
    if mods:
        problems.append("go.mod requires " + ", ".join(f"{m} {v}" for m, v in mods)
                        + " (the Go module is standard library only)")
    for mod, files in third_party_imports().items():
        problems.append(f"Python imports {mod} in {', '.join(files)} (the lanes are standard library only)")
    if problems:
        raise Rule("; ".join(problems))


def build(version):
    commit = git_commit()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{PURL_NS}@{version}#{commit}")
    go_ver = go_toolchain()
    stdlib_ref = f"pkg:golang/stdlib@{go_ver}"
    lanes_ref = f"{PURL_NS}@{version}#fleet-kit-lanes"

    components = []
    deps = []
    for cmd in go_commands():
        ref = f"{PURL_NS}@{version}#cmd/{cmd}"
        components.append({
            "type": "application", "bom-ref": ref, "name": cmd, "version": version,
            "description": f"Go command built from cmd/{cmd}",
            "purl": f"{PURL_NS}@{version}#cmd/{cmd}",
        })
        deps.append({"ref": ref, "dependsOn": [stdlib_ref]})
    components.append({
        "type": "application", "bom-ref": lanes_ref, "name": "fleet-kit-lanes", "version": version,
        "description": "The bash runners and Python lanes under fleet-kit/fleet (standard library only)",
    })
    deps.append({"ref": lanes_ref, "dependsOn": ["platform:python3", "platform:bash"]})
    components.append({
        "type": "library", "bom-ref": stdlib_ref, "name": "go-standard-library", "version": go_ver,
        "purl": stdlib_ref, "description": "The Go standard library of the toolchain that builds the commands",
    })
    for path, ver in go_modules():  # none today: check() refuses them
        ref = f"pkg:golang/{path}@{ver}"
        components.append({"type": "library", "bom-ref": ref, "name": path, "version": ver, "purl": ref})
    for name in ("python3", "bash"):
        components.append({
            "type": "platform", "bom-ref": f"platform:{name}", "name": name,
            "description": f"{name} as provided by the host operating system (the Fedora package); not shipped with the fleet",
        })
    components.sort(key=lambda c: (c["type"], c["name"]))
    deps.sort(key=lambda d: d["ref"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "scripts/sbom.py"}]},
            "component": {"type": "application", "bom-ref": f"{PURL_NS}@{version}", "name": "cti-agent",
                          "version": version, "description": "CTI Agent Fleet"},
            "properties": [{"name": "git.commit", "value": commit},
                           {"name": "dependencies.third-party", "value": "none"}],
        },
        "components": components,
        "dependencies": deps,
    }


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--version")
    ap.add_argument("--check", action="store_true", help="verify the no-dependency rule and write nothing")
    a = ap.parse_args(argv)
    try:
        check()
    except Rule as e:
        print(f"sbom: the no-dependency rule is broken: {e}", file=sys.stderr)
        return 1
    if a.check:
        print("sbom: ok - no third-party Go modules, no third-party Python imports")
        return 0
    version = a.version or git_version()
    out = a.out or os.path.join(ROOT, "dist", "sbom", f"cti-agent-{re.sub(r'[^A-Za-z0-9._-]', '_', version)}.cdx.json")
    bom = build(version)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bom, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"sbom: wrote {out} ({len(bom['components'])} components, version {version})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
