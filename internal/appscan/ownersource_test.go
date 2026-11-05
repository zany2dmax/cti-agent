package appscan

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const snapshotJSON = `{
 "format": "cti-owners/1",
 "generated": "2026-11-05T12:00:00Z",
 "change": 7,
 "apps": [
  {"app": "id:101", "owner": "Lead@Example.com", "component": "Web", "watchers": ["qa@example.com"], "covers": ["www.example.com"]},
  {"app": "Name Only App", "owner": "two@example.com"},
  {"app": "id:102", "owner": "", "covers": ["shop.example.com"]},
  {"app": "id:103", "owner": "not-an-email"}
 ],
 "sites": [{"domain": "brochure.example.net", "owner": "web@example.com"}],
 "allowedDomains": ["Example.com", " "]
}`

// The snapshot and the file mean the same thing for the same entries.
func TestSnapshotMatchesTheFile(t *testing.T) {
	snap, sp, err := ParseOwnersSnapshot(strings.NewReader(snapshotJSON))
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := ParseOwners(strings.NewReader(`
id:101 | Lead@Example.com | Web | covers=www.example.com | watchers=qa@example.com
Name Only App | two@example.com
id:102 | OWNER@example.com | covers=shop.example.com
id:103 | not-an-email
site:brochure.example.net | web@example.com
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range [][2]string{{"101", ""}, {"", "name only app"}} {
		a, okA := snap.For(q[0], q[1])
		b, okB := file.For(q[0], q[1])
		a.Line, b.Line = 0, 0
		if okA != okB || !reflect.DeepEqual(a, b) {
			t.Errorf("%v: snapshot %+v %v, file %+v %v", q, a, okA, b, okB)
		}
	}
	if got := snap.CoversFor("102", ""); !reflect.DeepEqual(got, []string{"shop.example.com"}) {
		t.Errorf("covers-only entry lost: %v", got)
	}
	if _, ok := snap.For("103", ""); ok {
		t.Error("an owner that is not an email address was accepted")
	}
	if w, ok := snap.ForSite("brochure.example.net"); !ok || w.Email != "web@example.com" {
		t.Errorf("site %+v %v", w, ok)
	}
	if len(sp) != 2 { // 102 has no owner yet; 103 is not an email
		t.Errorf("problems %v", sp)
	}
	allow, managed := snap.AllowedDomains()
	if !managed || !reflect.DeepEqual(allow, []string{"example.com"}) {
		t.Errorf("allow %v managed %v", allow, managed)
	}
	if _, managed := file.AllowedDomains(); managed {
		t.Error("app-owners.txt keeps no allowlist")
	}
}

func TestSnapshotRefusesWhatItCannotTrust(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       "id:1 | a@example.com",
		"other format":   `{"format": "cti-owners/2", "apps": []}`,
		"no format":      `{"apps": []}`,
		"truncated json": snapshotJSON[:40],
	} {
		if _, _, err := ParseOwnersSnapshot(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A component that would be read as another field is not passed through.
	o, p, err := ParseOwnersSnapshot(strings.NewReader(`{"format":"cti-owners/1","apps":[
		{"app":"id:1","owner":"a@example.com","component":"watchers=evil@example.org"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if w, _ := o.For("1", ""); len(w.Watchers) != 0 || len(p) != 1 {
		t.Errorf("component smuggled a watcher: %+v %v", w, p)
	}
}

// ownedHere points the snapshot at dir and trusts the test's own uid as its
// owner, standing in for root.
func ownedHere(t *testing.T, dir string) {
	t.Helper()
	oldDir, oldUID := ownersDir, trustedUID
	ownersDir, trustedUID = dir, uint32(os.Getuid()) // #nosec G115 -- a uid
	t.Cleanup(func() { ownersDir, trustedUID = oldDir, oldUID })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredOwnerSource(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app-owners.txt")
	snap := filepath.Join(dir, "owners.json")
	t.Setenv("APPSCAN_OWNERS_FILE", file)
	ownedHere(t, dir)
	if err := os.WriteFile(file, []byte("id:9 | file@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No snapshot: the file.
	o, src, _, err := LoadConfiguredOwners()
	if err != nil || src.Name() != file {
		t.Fatalf("src %v err %v", src.Name(), err)
	}
	if w, ok := o.For("9", ""); !ok || w.Email != "file@example.com" {
		t.Fatalf("file owner %+v", w)
	}

	// A snapshot: it wins, and the leftover file is pointed out.
	if err := os.WriteFile(snap, []byte(snapshotJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	o, src, p, err := LoadConfiguredOwners()
	if err != nil || !strings.HasPrefix(src.Name(), snap) {
		t.Fatalf("src %v err %v", src.Name(), err)
	}
	if _, ok := o.For("9", ""); ok {
		t.Error("the file was still read beside the snapshot")
	}
	if !strings.Contains(strings.Join(p, "\n"), "no longer read") {
		t.Errorf("leftover file not mentioned: %v", p)
	}

	// A snapshot that cannot be read is an error - never the file instead.
	if err := os.WriteFile(snap, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil {
		t.Error("a broken snapshot fell back to the file")
	}
	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(snap, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil {
		t.Error("a directory in the snapshot's place fell back to the file")
	}
}

// fleet-owners imports the shared sample into this golden snapshot
// (fleet-kit/tests/test_owners.py checks that); read here, it must mean what
// the sample file means to ParseOwners. The two languages meet at this file.
func TestGoldenSnapshotMatchesTheSampleFile(t *testing.T) {
	gf, err := os.Open(filepath.Join("testdata", "owners-snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gf.Close() }()
	snap, _, err := ParseOwnersSnapshot(gf)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := os.Open(filepath.Join("..", "..", "fleet-kit", "tests", "testdata", "app-owners-sample.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sf.Close() }()
	file, _, err := ParseOwners(sf)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range [][2]string{{"101", ""}, {"102", ""}, {"103", ""}, {"104", ""}, {"105", ""}, {"", "name only app"}, {"", "Customer Portal"}} {
		a, okA := snap.For(q[0], q[1])
		b, okB := file.For(q[0], q[1])
		a.Line, b.Line, a.App, b.App = 0, 0, "", ""
		// owners.db keeps watchers sorted; their order means nothing.
		sort.Strings(a.Watchers)
		sort.Strings(b.Watchers)
		if okA != okB || !reflect.DeepEqual(a, b) {
			t.Errorf("%v: snapshot %+v %v, file %+v %v", q, a, okA, b, okB)
		}
		if got, want := snap.CoversFor(q[0], q[1]), file.CoversFor(q[0], q[1]); !reflect.DeepEqual(got, want) {
			t.Errorf("%v: covers %v, file %v", q, got, want)
		}
	}
	for _, d := range []string{"brochure.example.net", "parked.example.net", "gallery.example.net"} {
		a, okA := snap.ForSite(d)
		b, okB := file.ForSite(d)
		a.Line, b.Line, a.App, b.App = 0, 0, "", ""
		if okA != okB || !reflect.DeepEqual(a, b) {
			t.Errorf("site %s: snapshot %+v %v, file %+v %v", d, a, okA, b, okB)
		}
	}
}

func TestSnapshotIsRequiredOnceTheDatabaseExists(t *testing.T) {
	dir := t.TempDir()
	ownedHere(t, dir)
	file := filepath.Join(dir, "app-owners.txt")
	t.Setenv("APPSCAN_OWNERS_FILE", file)
	if err := os.WriteFile(file, []byte("id:9 | file@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "owners.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("owners.db with no snapshot read the file instead: %v", err)
	}
}

func TestSnapshotMustBeRootsAlone(t *testing.T) {
	dir := t.TempDir()
	ownedHere(t, dir)
	snap := filepath.Join(dir, "owners.json")
	if err := os.WriteFile(snap, []byte(snapshotJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err != nil {
		t.Fatalf("a 0640 snapshot owned by its owner: %v", err)
	}
	if err := os.Chmod(snap, 0o660); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil {
		t.Error("a group-writable snapshot was trusted")
	}
	if err := os.Chmod(snap, 0o640); err != nil { // #nosec G302 -- restored
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil { // #nosec G302 -- the case under test
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil {
		t.Error("a snapshot in a group-writable directory was trusted")
	}
	trustedUID = uint32(os.Getuid()) + 1 // #nosec G115 -- a uid
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfiguredOwners(); err == nil {
		t.Error("a snapshot owned by someone else was trusted")
	}
}

func TestSnapshotEntriesAreOneValueEach(t *testing.T) {
	o, p, err := ParseOwnersSnapshot(strings.NewReader(`{"format":"cti-owners/1","apps":[
		{"app":"id:1","owner":"a@example.com","watchers":["x@evil.example,y@example.com","qa@example.com"]},
		{"app":"Customer  Portal","owner":"b@example.com"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if w, _ := o.For("1", ""); !reflect.DeepEqual(w.Watchers, []string{"qa@example.com"}) || len(p) != 1 {
		t.Errorf("watchers %v problems %v", w.Watchers, p)
	}
	if _, ok := o.For("", "customer portal"); !ok {
		t.Error("runs of spaces in a name changed what it matches")
	}
}
