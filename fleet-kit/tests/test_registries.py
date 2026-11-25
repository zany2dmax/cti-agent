#!/usr/bin/env python3
"""Every vendor package is reached from its one selection point.

INTERFACES.md section 5: a tool goes behind an interface as a package beside
the others, plus one line in the single place that chooses the implementation.
A package added without that line is dead code a reader takes for a working
option; a line removed leaves a vendor nobody can select. This holds each
registry to its packages. The lookup providers have a Go test of their own
(internal/vulnlookup/providers: TestEveryProviderPackageHasAName).

    python3 -m unittest discover -s fleet-kit/tests
"""
import pathlib
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
MODULE = "github.com/zany2dmax/cti-agent"

# (the interface's package, folders under it that are not vendors, the file
# that selects among them)
REGISTRIES = [
    ("internal/appscan", {"testdata"}, "cmd/cti-appscan/wiring.go"),
    ("internal/domains", set(), "cmd/cti-domains/main.go"),
    ("internal/vulnlookup", {"providers"}, "internal/vulnlookup/providers/providers.go"),
]


def vendors(area, skip):
    root = REPO / area
    return sorted(d.name for d in root.iterdir()
                  if d.is_dir() and d.name not in skip
                  and any(p.suffix == ".go" and not p.name.endswith("_test.go") for p in d.iterdir()))


class EveryVendorIsSelectable(unittest.TestCase):
    def test_each_vendor_package_is_imported_where_it_is_chosen(self):
        for area, skip, chooser in REGISTRIES:
            text = (REPO / chooser).read_text(encoding="utf-8")
            for v in vendors(area, skip):
                with self.subTest(vendor=f"{area}/{v}"):
                    self.assertIn(f'"{MODULE}/{area}/{v}"', text,
                                  f"{area}/{v} is not imported by {chooser}, its one selection point")

    def test_the_registries_are_not_empty(self):
        # A moved folder would make the test above pass by checking nothing.
        for area, skip, _ in REGISTRIES:
            with self.subTest(area=area):
                self.assertTrue(vendors(area, skip), f"no vendor package found under {area}")

    def test_only_the_wiring_file_names_a_scanner_vendor(self):
        # cmd/cti-appscan keeps its vendor imports in wiring.go alone (its own
        # Go test enforces it too); the selection point above relies on that.
        for p in (REPO / "cmd" / "cti-appscan").glob("*.go"):
            if p.name in ("wiring.go",) or p.name.endswith("_test.go"):
                continue
            with self.subTest(file=p.name):
                self.assertNotIn(f'"{MODULE}/internal/appscan/qualys"', p.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
