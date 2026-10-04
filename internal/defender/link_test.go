package defender

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Shapes taken from a real notification, with every real identifier replaced.
// The production email names our subscription, and this repository is public.
const (
	portalURL = "https://portal.azure.com/#view/Microsoft_Azure_Security/" +
		"AttackPathType.ReactView/attackPathType/00000000-aaaa-bbbb-cccc-111111111111/" +
		"attackPathTypeName/Internet%20exposed%20Azure%20VM/attackPathId/" +
		"99999999-dddd-eeee-ffff-222222222222"

	azureRedirect = "https://eur.safelink.emails.azure.net/redirect/?destination=" +
		"https%3A%2F%2Fportal.azure.com%2F%23view%2FMicrosoft_Azure_Security" +
		"&p=bT0xMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUmcz1hYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUmdT1hZW8mbD1wb3J0YWwuYXp1cmUuY29t"
)

// proofpoint builds a urldefense v3 wrapper the way Proofpoint actually does:
// each special character replaced by "*", and the characters themselves
// carried in order as url-safe base64 after "__;".
//
// The dictionary has to be RIGHT. The first version of this helper hardcoded
// "JSUl" - three percent signs - for a URL containing five, which the decoder
// then quietly tolerated. Fixing the decoder to refuse an inconsistent
// wrapper, which is what a security check should do, immediately broke this
// test. A fixture that could not be produced by the system under test is not
// a fixture.
func proofpoint(inner string) string {
	var wrapped strings.Builder
	var dict []byte
	for i := 0; i < len(inner); i++ {
		if inner[i] == '%' {
			wrapped.WriteByte('*')
			dict = append(dict, '%')
			continue
		}
		wrapped.WriteByte(inner[i])
	}
	return "https://urldefense.com/v3/__" + wrapped.String() + "__;" +
		strings.TrimRight(base64.URLEncoding.EncodeToString(dict), "=") +
		"!!ABcDeFg!HiJkLmNoPqRs$"
}

func TestARealPortalLinkSurvivesBothWrappers(t *testing.T) {
	got, err := UnwrapPortalLink(proofpoint(azureRedirect))
	if err != nil {
		t.Fatalf("a legitimate link was rejected: %v", err)
	}
	if !strings.HasPrefix(got, "https://portal.azure.com/") {
		t.Errorf("unwrapped to %q", got)
	}
}

func TestAnUnwrappedPortalLinkIsAlsoAccepted(t *testing.T) {
	// Microsoft does not always wrap, and neither does a forwarded copy.
	got, err := UnwrapPortalLink(portalURL)
	if err != nil {
		t.Fatalf("a bare portal link was rejected: %v", err)
	}
	if got == "" {
		t.Error("returned empty")
	}
}

func TestAnythingThatIsNotThePortalIsRefused(t *testing.T) {
	// The mailbox accepts mail from anyone, so a forged Defender notification
	// is cheap and is aimed at precisely the person who reads this digest.
	// These are the near-misses a suffix check or a "contains" check would
	// have let through.
	for name, bad := range map[string]string{
		"lookalike suffix":   "https://portal.azure.com.evil.example/#view/x",
		"lookalike prefix":   "https://evilportal.azure.com/#view/x",
		"subdomain":          "https://portal.azure.com.cdn.evil.example/x",
		"userinfo trick":     "https://portal.azure.com@evil.example/x",
		"plain http":         "http://portal.azure.com/#view/x",
		"different ms host":  "https://login.microsoftonline.com/common",
		"wrapped lookalike":  proofpoint("https://portal.azure.com.evil.example/x"),
		"wrapped redirector": proofpoint("https://eur.safelink.emails.azure.net/redirect/?destination=https%3A%2F%2Fevil.example%2Fx"),
	} {
		got, err := UnwrapPortalLink(bad)
		if err == nil {
			t.Errorf("%s: accepted %q -> %q", name, bad, got)
			continue
		}
		if got != "" {
			t.Errorf("%s: returned a URL alongside an error: %q", name, got)
		}
	}
}

func TestTheUserinfoTrickIsWhatHostnameIsFor(t *testing.T) {
	// https://portal.azure.com@evil.example/ has "portal.azure.com" in it, and
	// goes to evil.example. Hostname() is the only thing in the chain that
	// gets this right, so it gets its own test.
	if _, err := UnwrapPortalLink("https://portal.azure.com@evil.example/x"); !errors.Is(err, ErrNotPortal) {
		t.Errorf("err = %v, want ErrNotPortal", err)
	}
}

func TestAnUnparseableOrEmptyLinkIsAnErrorNotAGuess(t *testing.T) {
	for _, bad := range []string{"", "   ", "://nonsense", "not a url at all"} {
		if got, err := UnwrapPortalLink(bad); err == nil {
			t.Errorf("accepted %q -> %q", bad, got)
		}
	}
}

func TestAnUndecodableProofpointWrapperStillGetsChecked(t *testing.T) {
	// urldefense v3 has a base64 dictionary form this does not decode. A
	// half-decoded URL must still fail the portal check rather than slip
	// through - guessing at the dictionary would produce a plausible-looking
	// wrong URL, which is worse than not decoding at all.
	if _, err := UnwrapPortalLink("https://urldefense.com/v3/__https:**Aevil.example**Ax__;JSU!!x!y$"); err == nil {
		t.Error("an undecodable wrapper produced an accepted URL")
	}
}

func TestTheTrackerGivesASecondSourceForTheSubscription(t *testing.T) {
	// The email states the subscription in its Scope IDs row too. Two
	// independent sources mean a disagreement is detectable - and a
	// disagreement means the email was not built the way this parser assumes,
	// which is a reason to distrust the whole parse rather than to pick one.
	got, ok := SubscriptionFromTracker(azureRedirect)
	if !ok {
		t.Fatal("the tracker parameter did not yield a subscription")
	}
	if got != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("subscription = %q", got)
	}
}

func TestTheTrackerFailsQuietlyWhenItIsNotThere(t *testing.T) {
	for _, s := range []string{portalURL, "", "https://example.com/?p=not-base64!!"} {
		if got, ok := SubscriptionFromTracker(s); ok {
			t.Errorf("%q yielded %q", s, got)
		}
	}
}
