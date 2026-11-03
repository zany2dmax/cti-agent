package mailer

import (
	"reflect"
	"strings"
	"testing"
)

func TestOwnerAudience(t *testing.T) {
	to, cc, refused, err := OwnerAudience("Lead@Example.com",
		[]string{"qa@dev-shop.example", "pm@exmaple.com", "lead@example.com", "not-an-address"},
		"example.com, @dev-shop.example")
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
	if _, _, _, err := OwnerAudience("lead@example.com", nil, " "); err == nil || !strings.Contains(err.Error(), OwnerAllowVar) {
		t.Errorf("unset allowlist: %v", err)
	}
	if _, _, _, err := OwnerAudience("lead@exmaple.com", []string{"qa@example.com"}, "example.com"); err == nil {
		t.Error("an owner outside the domains must refuse the send")
	}
	// A subdomain is a different domain.
	if _, _, _, err := OwnerAudience("lead@mail.example.com", nil, "example.com"); err == nil {
		t.Error("subdomain accepted")
	}
}
