package safelink

import (
	"errors"
	"strings"
	"testing"
)

// Both of these are the shapes seen in production mail this week. The second
// is why this package decodes the dictionary instead of assuming "*" is "%".

const (
	// Dictionary "Iw" decodes to "#", so the single * is a fragment marker.
	qualysWrapped = "https://urldefense.com/v3/__https://qualysguard.qg3.apps.qualys.com" +
		"/was/*/reports/online-reports/email-report/scan/25080057__;Iw!!F7TK!x$"

	// Dictionary "JSUlJSU" decodes to "%%%%%", so every * is a percent sign.
	azureWrapped = "https://urldefense.com/v3/__https://eur.safelink.emails.azure.net" +
		"/redirect/?destination=https*3A*2F*2Fportal.azure.com*2F*23view&p=abc__;JSUlJSU!!F7TK!y$"
)

func TestTheSubstitutionDictionaryIsDecodedNotAssumed(t *testing.T) {
	// The first version of this assumed "*" always meant "%". That is true for
	// the Azure link by coincidence and false for the Qualys one, where it
	// produced ".../was/%/reports/" - an invalid percent-escape. The link was
	// then dropped as unverifiable, which is the right failure for the wrong
	// reason: nothing was wrong with the mail.
	got, err := Unwrap(qualysWrapped, "qualysguard.qg3.apps.qualys.com")
	if err != nil {
		t.Fatalf("a real Qualys link was rejected: %v", err)
	}
	if !strings.Contains(got, "/was/#/reports/") {
		t.Errorf("got %q, want the # restored from the dictionary", got)
	}
}

func TestBothVendorsDecodeWithTheSameCode(t *testing.T) {
	if _, err := Unwrap(azureWrapped, "portal.azure.com"); err != nil {
		t.Errorf("the Azure link no longer decodes: %v", err)
	}
}

func TestAnAllowlistIsRequired(t *testing.T) {
	// Calling with no allowed hosts must not mean "anything goes".
	if _, err := Unwrap("https://example.com/"); err == nil {
		t.Error("an empty allowlist permitted a link")
	}
}

func TestTheNearMissesAllFail(t *testing.T) {
	for name, bad := range map[string]string{
		"suffix lookalike":  "https://portal.azure.com.evil.example/x",
		"prefix lookalike":  "https://evilportal.azure.com/x",
		"userinfo trick":    "https://portal.azure.com@evil.example/x",
		"plain http":        "http://portal.azure.com/x",
		"wrapped lookalike": "https://urldefense.com/v3/__https://portal.azure.com.evil.example/x__;!!A!b$",
	} {
		if got, err := Unwrap(bad, "portal.azure.com"); err == nil {
			t.Errorf("%s: accepted %q -> %q", name, bad, got)
		} else if !errors.Is(err, ErrHostNotAllowed) && !strings.Contains(err.Error(), "scheme") {
			t.Errorf("%s: unexpected error kind: %v", name, err)
		}
	}
}

func TestAnInconsistentWrapperIsRefusedNotGuessedAt(t *testing.T) {
	// A dictionary too short for the number of placeholders means this is not
	// the format we think it is. A half-decoded URL that happens to parse is
	// exactly the plausible wrong answer the allowlist exists to catch, and it
	// must not get that far.
	for _, bad := range []string{
		// One character of dictionary, three substitution slots.
		"https://urldefense.com/v3/__https://x.example/*/*/*__;Iw!!A!b$",
		// A dictionary that is not base64 at all.
		"https://urldefense.com/v3/__https://x.example/*__;a.b!!A$",
	} {
		if _, err := Unwrap(bad, "x.example"); err == nil {
			t.Errorf("accepted an inconsistent wrapper: %q", bad)
		}
	}
}
