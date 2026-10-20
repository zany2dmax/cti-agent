package qualys

import (
	"context"
	"strings"
	"testing"
)

func appsPage(more bool, apps ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><ServiceResponse><responseCode>SUCCESS</responseCode>` +
		`<hasMoreRecords>` + map[bool]string{true: "true", false: "false"}[more] + `</hasMoreRecords><data>` +
		strings.Join(apps, "") + `</data></ServiceResponse>`
}

func app(id, name, url string) string {
	// A nested element with its own <id> and <name>, as real responses carry,
	// must not be read as the web app's.
	return `<WebApp><id>` + id + `</id><name><![CDATA[` + name + `]]></name><url><![CDATA[` + url + `]]></url>` +
		`<defaultProfile><id>9</id><name>Initial profile</name></defaultProfile></WebApp>`
}

func TestWebAppsArePagedAndSortedByName(t *testing.T) {
	api, bodies := stub(t, func(_ string, call int) (int, string) {
		if call == 1 {
			return 200, appsPage(true, app("200", "Zeta Shop", "https://z.example.com"), app("101", "alpha portal", "https://a.example.com"))
		}
		return 200, appsPage(false, app("300", "Mid App", "https://m.example.com"))
	})
	got, err := api.WebApps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "alpha portal" || got[0].ID != "101" || got[2].Name != "Zeta Shop" {
		t.Errorf("apps %+v", got)
	}
	if strings.Contains((*bodies)[0], "<filters>") {
		t.Errorf("first page sent an empty filter:\n%s", (*bodies)[0])
	}
	if !strings.Contains((*bodies)[1], `field="id" operator="GREATER">200<`) {
		t.Errorf("second page not keyed after the highest id:\n%s", (*bodies)[1])
	}
}

func TestAWebAppListErrorIsAnError(t *testing.T) {
	api, _ := stub(t, func(string, int) (int, string) {
		return 200, `<ServiceResponse><responseCode>UNAUTHORIZED</responseCode><responseErrorDetails><errorMessage>no WAS</errorMessage></responseErrorDetails></ServiceResponse>`
	})
	if _, err := api.WebApps(context.Background()); err == nil || !strings.Contains(err.Error(), "no WAS") {
		t.Errorf("err %v", err)
	}
}
