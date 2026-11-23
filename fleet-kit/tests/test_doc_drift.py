#!/usr/bin/env python3
"""ARCHITECTURE.md names every binary, package and fleet script that exists.

It drifted for a month: "the eleven binaries" over a table of thirteen, with
eighteen in cmd/, and a dozen internal packages and four fleet scripts missing
from the layout. Nothing failed, so nobody noticed. This test derives the lists
from the tree, not from a hand-kept copy, and fails in both directions: a thing
that exists and is not documented, and a thing documented that no longer
exists.

    python3 -m unittest discover -s fleet-kit/tests
"""
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
ARCH = REPO / "ARCHITECTURE.md"

NUMBERS = ["zero", "one", "two", "three", "four", "five", "six", "seven",
           "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen",
           "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty",
           "twenty-one", "twenty-two", "twenty-three", "twenty-four",
           "twenty-five", "twenty-six", "twenty-seven", "twenty-eight",
           "twenty-nine", "thirty"]


def binaries():
    """Every cmd/<name> that builds a command (has a non-test .go file)."""
    return sorted(d.name for d in (REPO / "cmd").iterdir()
                  if d.is_dir() and any(not f.name.endswith("_test.go")
                                        for f in d.glob("*.go")))


def packages():
    """Every internal/ directory holding a non-test .go file, as internal/x/y."""
    out = set()
    for f in (REPO / "internal").rglob("*.go"):
        if f.name.endswith("_test.go") or "testdata" in f.parts:
            continue
        out.add(f.parent.relative_to(REPO).as_posix())
    return sorted(out)


def fleet_scripts():
    """Every file in fleet-kit/fleet/bin that the installer ships."""
    return sorted(f.name for f in (REPO / "fleet-kit/fleet/bin").iterdir()
                  if f.is_file() and not f.name.startswith((".", "__")))


def layout(text):
    """The ```text block under "## Project layout"."""
    m = re.search(r"^## Project layout\n.*?```text\n(.*?)```", text, re.S | re.M)
    return m.group(1) if m else ""


def binaries_table(text):
    """Binary names in the first column of the "## The N binaries" table."""
    m = re.search(r"^## The [\w-]+ binaries\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return re.findall(r"^\| `([\w-]+)` \|", m.group(1) if m else "", re.M)


class ArchitectureMatchesTheTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = ARCH.read_text(encoding="utf-8")
        cls.layout = layout(cls.text)
        cls.table = binaries_table(cls.text)

    def test_the_sections_this_test_reads_exist(self):
        # A renamed heading must not turn every check below into a quiet pass.
        self.assertTrue(self.layout, 'no ```text block under "## Project layout"')
        self.assertTrue(self.table, 'no table under "## The N binaries"')

    def test_every_spelled_out_binary_count_is_the_real_count(self):
        n = len(binaries())
        want = NUMBERS[n] if n < len(NUMBERS) else str(n)
        said = re.findall(r"\b([\w-]+) binaries\b", self.text, re.I)
        said += re.findall(r"\b[Aa]ll ([\w-]+) (?:are stdlib-only|into bin/)", self.text)
        counts = [w.lower() for w in said if w.lower() in NUMBERS or w.isdigit()]
        self.assertTrue(counts, "ARCHITECTURE.md states no binary count")
        wrong = sorted({w for w in counts if w != want})
        self.assertEqual(wrong, [], f"cmd/ has {n} binaries ({want}); ARCHITECTURE.md also says {wrong}")

    def test_every_binary_has_a_row_and_every_row_a_binary(self):
        have, rows = set(binaries()), set(self.table)
        self.assertEqual(sorted(have - rows), [], "binaries with no row in the binaries table")
        self.assertEqual(sorted(rows - have), [], "rows in the binaries table for no binary in cmd/")

    def test_every_binary_is_in_the_layout(self):
        missing = [b for b in binaries() if f"cmd/{b}/" not in self.layout]
        self.assertEqual(missing, [], "cmd/ directories missing from the project layout")
        gone = sorted(set(re.findall(r"^cmd/([\w-]+)/", self.layout, re.M)) - set(binaries()))
        self.assertEqual(gone, [], "project layout names cmd/ directories that do not exist")

    def test_every_package_is_in_the_layout(self):
        listed = set(re.findall(r"^(internal/[\w/-]+?)/\s", self.layout, re.M))
        missing = [p for p in packages() if p not in listed]
        self.assertEqual(missing, [], "internal/ packages missing from the project layout")
        gone = sorted(p for p in listed if not (REPO / p).is_dir())
        self.assertEqual(gone, [], "project layout names internal/ directories that do not exist")

    def test_every_fleet_script_is_in_the_layout(self):
        words = set(re.findall(r"[\w-]+", self.layout))
        missing = [s for s in fleet_scripts() if s not in words]
        self.assertEqual(missing, [], "fleet-kit/fleet/bin scripts missing from the project layout")



class PdfSourcesArePlainASCII(unittest.TestCase):
    """task cheatsheet:pdf and task docs:pdf run pdflatex, which stops on a
    character outside ASCII. Each task checks first, but only when someone
    builds a PDF: an em dash sat in CHEATSHEET.md from 25f3141 until
    2026-11-23, and the PDF could not be built the whole time. This makes
    `task test` say so the day it goes in."""

    def test_every_pdf_source_is_ascii(self):
        bad = []
        for p in [REPO / "CHEATSHEET.md", *sorted((REPO / "docs").glob("*.md"))]:
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                for c in line:
                    if ord(c) > 127:
                        bad.append(f"{p.relative_to(REPO)}:{n}: U+{ord(c):04X} in {line.strip()[:60]!r}")
                        break
        self.assertEqual(bad, [], "pdflatex cannot take these; write them in ASCII")


if __name__ == "__main__":
    unittest.main(verbosity=2)
