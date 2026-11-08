package supplier

import (
	"context"
	"errors"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/xlsx/xlsxtest"
)

// fakeSource records every download, so a test can say which files were opened.
type fakeSource struct {
	atts    []Attachment
	content map[string][]byte
	opened  []string
}

func (f *fakeSource) Attachments(context.Context, string) ([]Attachment, error) { return f.atts, nil }

func (f *fakeSource) Content(_ context.Context, _, id string, _ int64) ([]byte, error) {
	f.opened = append(f.opened, id)
	b, ok := f.content[id]
	if !ok {
		return nil, errors.New("no such attachment")
	}
	return b, nil
}

func file(id, name string, size int64) Attachment {
	return Attachment{ID: id, Name: name, Size: size, IsFile: true}
}

func TestOnlyTheFormIsEverDownloaded(t *testing.T) {
	form := workbook(t, completeForm)
	src := &fakeSource{
		atts: []Attachment{
			file("form", "New Supplier Form 02.01.26 (1).xlsx", 47000),
			file("w9pdf", "2026 Example W-9 (2).pdf", 438000),
			file("w9xlsx", "Example W9.xlsx", 20000),
			file("w9dash", "w-9_example.xlsx", 20000),
			file("bank", "Example Banking Remit Instructions.pdf", 476000),
			file("bankx", "Banking Info.xlsx", 20000),
			file("void", "voided check.xlsx", 20000),
			file("big", "Another Supplier Form.xlsx", 50<<20),
			{ID: "logo", Name: "image001.png", Size: 3000, Inline: true, IsFile: true},
			{ID: "msg", Name: "forwarded.xlsx", IsFile: false},
			file("doc", "terms.docx", 1000),
		},
		content: map[string][]byte{"form": form},
	}
	reads, skipped, err := ReadForms(context.Background(), src, Policy{}, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if len(src.opened) != 1 || src.opened[0] != "form" {
		t.Fatalf("downloaded %v, want only the form", src.opened)
	}
	if len(reads) != 1 || reads[0].Err != nil || reads[0].Form.Name != "Example Geo Services, Inc." {
		t.Fatalf("reads = %+v", reads)
	}
	// Everything but the form and the inline image is reported as left alone.
	if len(skipped) != 9 {
		t.Errorf("skipped %d, want 9: %+v", len(skipped), skipped)
	}
	for _, s := range skipped {
		if s.Name == "image001.png" {
			t.Error("an inline signature image was reported as a decision")
		}
	}
}

func TestAWordInsideAnotherWordIsNotATaxForm(t *testing.T) {
	p := Policy{}
	for _, name := range []string{"First Choice Supplier Form.xlsx", "Banksia Landscaping Form.xlsx", "Tax-Free Supplies Form.xlsx"} {
		ok, why := p.Readable(file("x", name, 1000))
		want := name != "Tax-Free Supplies Form.xlsx" // "tax" is a whole word there
		if ok != want {
			t.Errorf("%q readable=%v (%s), want %v", name, ok, why, want)
		}
	}
}

func TestThePolicyCanAllowOtherTypesButNeverASensitiveName(t *testing.T) {
	p := Policy{Exts: []string{".xlsx", ".xlsm"}, MaxBytes: 1000}
	if ok, _ := p.Readable(file("a", "form.xlsm", 500)); !ok {
		t.Error("an allowed type was refused")
	}
	if ok, _ := p.Readable(file("a", "form.xlsm", 5000)); ok {
		t.Error("a file over the size limit was allowed")
	}
	if ok, _ := p.Readable(file("a", "W-9.xlsm", 500)); ok {
		t.Error("a sensitive name was allowed")
	}
}

func TestAFileThatIsNotTheFormIsReportedNotDropped(t *testing.T) {
	other := xlsxtest.Build(t, map[string][][]string{"Budget": {{"a"}}}, []string{"Budget"})
	src := &fakeSource{
		atts:    []Attachment{file("b", "budget.xlsx", 1000), file("gone", "missing.xlsx", 1000)},
		content: map[string][]byte{"b": other},
	}
	reads, _, err := ReadForms(context.Background(), src, Policy{}, "m")
	if err != nil || len(reads) != 2 {
		t.Fatalf("reads %d, err %v", len(reads), err)
	}
	if reads[0].Err == nil || reads[1].Err == nil {
		t.Errorf("a non-form or a failed download looked like a form: %+v", reads)
	}
}
