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
import hashlib
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
    # FileNotFoundError (the tool is not installed) is left to the caller: git
    # and go each say what they are needed for.
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)  # nosec B603


def _try(*cmd):
    try:
        return run(*cmd)
    except FileNotFoundError:
        return None


def git_version():
    r = _try("git", "describe", "--tags", "--always", "--dirty")
    return r.stdout.strip() if r and r.returncode == 0 and r.stdout.strip() else "unknown"


def git_commit():
    r = _try("git", "rev-parse", "HEAD")
    return r.stdout.strip() if r and r.returncode == 0 else ""


def tree_fingerprint():
    """A hash of the uncommitted changes, so two different dirty trees at one
    commit do not share a serial number. Empty for a clean tree."""
    r = _try("git", "diff", "HEAD")
    if not r or r.returncode != 0 or not r.stdout:
        return ""
    return hashlib.sha256(r.stdout.encode("utf-8", "replace")).hexdigest()[:16]


def go_toolchain():
    r = _try("go", "env", "GOVERSION")
    v = r.stdout.strip() if r else ""
    return v[2:] if v.startswith("go") else (v or "unknown")


def go_modules():
    """(path, version) of every module the main module requires, as the go tool
    itself reads go.mod (`go mod edit -json`): Go accepts an indented `require`,
    a block, an inline form and quoted paths, and a regular expression over the
    text misses some of them."""
    for name in ("go.work", "vendor"):
        if os.path.exists(os.path.join(ROOT, name)):
            raise Rule(f"{name} exists: the module is standard library only, and a "
                       f"{name} is how third-party code would arrive")
    try:
        r = run("go", "mod", "edit", "-json")
    except FileNotFoundError:
        raise Rule("the go tool is not installed, so go.mod cannot be read; install Go to run the SBOM") from None
    if r.returncode != 0:
        raise Rule(f"go mod edit could not read go.mod: {r.stderr.strip()[:200]}")
    try:
        req = json.loads(r.stdout).get("Require") or []
    except ValueError:
        raise Rule("go mod edit -json gave output that is not JSON") from None
    return sorted({(m["Path"], m["Version"]) for m in req})


def go_commands():
    base = os.path.join(ROOT, "cmd")
    return sorted(d for d in os.listdir(base)
                  if os.path.isfile(os.path.join(base, d, "main.go")))


SCAN_DIRS = ("fleet-kit", "scripts")


def _walk(base):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "__pycache__", "node_modules"))
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def _head(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.readline()
    except (OSError, UnicodeDecodeError):
        return ""


def python_files():
    """Every Python file under fleet-kit and scripts, recursively: a .py file, or
    a file whose first line is a python shebang."""
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if os.path.isdir(base):
            for p in _walk(base):
                head = _head(p)
                if p.endswith(".py") or (head.startswith("#!") and "python" in head):
                    out.append(p)
    return out


def shell_files():
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(ROOT, d)
        if os.path.isdir(base):
            for p in _walk(base):
                head = _head(p)
                if p.endswith(".sh") or (head.startswith("#!") and re.search(r"\b(ba)?sh\b", head)):
                    out.append(p)
    return out


_HEREDOC = re.compile(r"python3?\b[^\n]*?<<-?\s*(['\"]?)(\w+)\1[^\n]*\n(.*?)\n\s*\2\b", re.S)
_DASH_C = re.compile(r"python3?\s+(?:-\w+\s+)*-c\s+(['\"])(.*?)\1", re.S)
_IMPORT_LINE = re.compile(r"^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b|import[ \t]+([A-Za-z_][\w., \t]*))", re.M)


def _snippet_imports(text):
    names = []
    for m in _IMPORT_LINE.finditer(text):
        if m.group(1):
            names.append(m.group(1).split(".")[0])
        else:
            names += [x.strip().split(" ")[0].split(".")[0] for x in m.group(2).split(",") if x.strip()]
    return names


def embedded_python(path):
    """The imports of Python written inside a shell script: a `python3 - <<EOF`
    heredoc, or `python3 -c '...'`. They cannot be parsed (shell variables are in
    them), so they are read by line, which is enough to see an import."""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    names = []
    for m in _HEREDOC.finditer(text):
        names += _snippet_imports(m.group(3))
    for m in _DASH_C.finditer(text):
        names += _snippet_imports(m.group(2).replace(";", "\n"))
    return names


def _dynamic_imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            if name in ("__import__", "import_module"):
                yield node.lineno


def third_party_imports():
    """{module: [files]} for every import that is not the standard library or a
    module sitting in the SAME directory as the file that imports it. A module of
    that name elsewhere in the tree is not on that file's path, so it does not
    excuse the import. Dynamic imports (__import__, import_module) cannot be
    checked, so they are reported as a module called "<dynamic import>"."""
    std = set(sys.stdlib_module_names)
    found = {}

    def note(mod, path):
        found.setdefault(mod, []).append(os.path.relpath(path, ROOT))

    for p in python_files():
        local = {os.path.splitext(n)[0] for n in os.listdir(os.path.dirname(p))}
        with open(p, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=p)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for n in names:
                if n not in std and n not in local:
                    note(n, p)
        if any(True for _ in _dynamic_imports(tree)):
            note("<dynamic import>", p)
    for p in shell_files():
        local = {os.path.splitext(n)[0] for n in os.listdir(os.path.dirname(p))}
        for n in embedded_python(p):
            if n not in std and n not in local:
                note(n, p)
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
    fingerprint = tree_fingerprint()
    # A serial number is unique per BOM: a dirty tree adds a hash of its changes,
    # so two different working trees at one commit do not share one.
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{PURL_NS}@{version}#{commit}#{fingerprint}")
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
    deps.append({"ref": lanes_ref, "dependsOn": ["platform:python3", "platform:bash", "platform:claude-code"]})
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
    # The heartbeat, the supplier judge and advisory triage run the Claude Code
    # CLI: third-party software the fleet executes and does not ship. It is the
    # host's, installed system-wide (root-owned), so no version is known here.
    components.append({
        "type": "application", "bom-ref": "platform:claude-code", "name": "claude-code",
        "description": "The Claude Code CLI (a Node application) that run-checkin, run-supplier and advisory triage execute; "
                       "installed on the host by the operator, not built or shipped here",
        "scope": "required",
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
                           {"name": "git.dirty", "value": "true" if fingerprint else "false"},
                           {"name": "dependencies.third-party", "value": "none (the Claude Code CLI is host software the fleet runs, listed as a platform component)"}],
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
    except SyntaxError as e:
        print(f"sbom: cannot read {os.path.relpath(e.filename or '?', ROOT)} line {e.lineno}: it does not parse, "
              f"so its imports cannot be checked", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"sbom: cannot read the tree: {e}", file=sys.stderr)
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
