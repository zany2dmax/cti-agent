package mailer

import (
	"reflect"
	"strings"
	"testing"
)

func TestOwnerAudience(t *testing.T) {
	to, cc, refused, err := OwnerAudience("Lead@Example.com",
		[]string{"qa@dev-shop.example", "pm@exmaple.com", "lead@example.com", "not-an-address"},
		"example.com, @dev-shop.example", OwnerAllowVar)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(to, []string{"Lead@Example.com"}) || !reflect.DeepEqual(cc, []string{"qa@dev-shop.example"}) {
		t.Errorf("to %v cc %v", to, cc)
	}
	if !reflect.DeepEqual(refused, []string{"pm@exmaple.com", "not-an-address"}) {
		t.Errorf("refused %v", refused)
	}
}

func TestOwnerAudienceRefuses(t *testing.T) {
	if _, _, _, err := OwnerAudience("lead@example.com", nil, " ", OwnerAllowVar); err == nil || !strings.Contains(err.Error(), OwnerAllowVar) {
		t.Errorf("unset allowlist: %v", err)
	}
	if _, _, _, err := OwnerAudience("lead@exmaple.com", []string{"qa@example.com"}, "example.com", OwnerAllowVar); err == nil {
		t.Error("an owner outside the domains must refuse the send")
	}
	// A subdomain is a different domain.
	if _, _, _, err := OwnerAudience("lead@mail.example.com", nil, "example.com", OwnerAllowVar); err == nil {
		t.Error("subdomain accepted")
	}
}

// WAS_OWNER_CC: the security team on every owner email, through the same domain
// check as a watcher, never repeated, and optional.
func TestTheSecurityTeamIsCopiedOnEveryOwnerEmail(t *testing.T) {
	to := []string{"owner@example.com"}
	cc := []string{"dev@agency.example"}
	got, refused := OwnerTeamCc(to, cc, "sec1@example.com, SEC2@example.com", "example.com,agency.example")
	want := []string{"dev@agency.example", "sec1@example.com", "SEC2@example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") || len(refused) != 0 {
		t.Errorf("cc = %v refused = %v, want %v", got, refused, want)
	}
}

func TestATeamAddressOutsideTheAllowedDomainsIsLeftOff(t *testing.T) {
	got, refused := OwnerTeamCc([]string{"owner@example.com"}, nil,
		"sec@example.com,typo@exmaple.com,not-an-address", "example.com")
	if strings.Join(got, ",") != "sec@example.com" {
		t.Errorf("cc = %v", got)
	}
	if strings.Join(refused, ",") != "typo@exmaple.com,not-an-address" {
		t.Errorf("refused = %v", refused)
	}
}

func TestATeamMemberAlreadyOnTheEmailIsNotRepeated(t *testing.T) {
	got, _ := OwnerTeamCc([]string{"Owner@Example.com"}, []string{"w@example.com"},
		"owner@example.com,W@EXAMPLE.COM,sec@example.com,sec@example.com", "example.com")
	if strings.Join(got, ",") != "w@example.com,sec@example.com" {
		t.Errorf("cc = %v", got)
	}
}

func TestNoTeamLeavesTheEmailAsItWas(t *testing.T) {
	cc := []string{"w@example.com"}
	got, refused := OwnerTeamCc([]string{"o@example.com"}, cc, "  ", "example.com")
	if strings.Join(got, ",") != "w@example.com" || refused != nil {
		t.Errorf("cc = %v refused = %v", got, refused)
	}
	got[0] = "changed"
	if cc[0] != "w@example.com" {
		t.Error("OwnerTeamCc changed the caller's slice")
	}
}
