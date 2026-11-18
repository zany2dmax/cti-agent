#!/usr/bin/env bash
# release-notes.sh - print one version's section of CHANGELOG.md.
#
#   scripts/release-notes.sh 1.6.6              # from ./CHANGELOG.md
#   scripts/release-notes.sh v1.5.1 path/CHANGELOG.md
#
# The GitHub release for a tag uses this as its notes
# (.github/workflows/release.yml), so the release page says exactly what the
# CHANGELOG says. A leading "v" on the version is ignored: tags are both
# "v1.5.1" and "1.6.6", headings are always "## 1.5.1 — YYYY-MM-DD".
#
# Prints the lines after the heading up to the next "## " heading, without the
# heading itself or the trailing blank lines and "---" rule. Exits 1, printing
# nothing, when the version has no heading or its section is empty: a release
# with no notes is a CHANGELOG that was never dated, and should fail loudly.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: release-notes.sh VERSION [CHANGELOG.md]" >&2
  exit 2
fi
ver="${1#v}"
file="${2:-CHANGELOG.md}"

# The version is matched as a literal string, never as a pattern.
if ! printf '%s' "$ver" | grep -Eq '^[0-9]+(\.[0-9]+){1,2}$'; then
  echo "release-notes.sh: '$1' is not a version like 1.6.6 or v1.5.1" >&2
  exit 2
fi
[ -r "$file" ] || { echo "release-notes.sh: cannot read $file" >&2; exit 2; }

notes="$(awk -v v="$ver" '
  index($0, "## ") == 1 {
    if (on) exit
    rest = substr($0, 4)
    # The heading is the version, then the end of the line or a space.
    if (substr(rest, 1, length(v)) == v && (length(rest) == length(v) || substr(rest, length(v) + 1, 1) == " ")) { on = 1; next }
  }
  on { line[++n] = $0 }
  END {
    # Trim blank lines at both ends, and the "---" rule between sections.
    first = 1
    while (first <= n && line[first] ~ /^[[:space:]]*$/) first++
    while (n >= first && (line[n] ~ /^[[:space:]]*$/ || line[n] == "---")) n--
    for (i = first; i <= n; i++) print line[i]
  }
' "$file")"

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "release-notes.sh: no section for $ver in $file - date its heading (## $ver — YYYY-MM-DD) and commit" >&2
  exit 1
fi
printf '%s\n' "$notes"
