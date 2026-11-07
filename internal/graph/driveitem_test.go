package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func driveStub(t *testing.T, status int, body string) (*Client, *string) {
	t.Helper()
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
			return
		}
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := New("tenant", "id", "secret")
	c.tokenEndpoint = srv.URL + "/tenant/oauth2/v2.0/token"
	c.graphBase = srv.URL
	_ = gotAuth
	return c, &gotPath
}

func TestReadsAFileByDriveAndItemId(t *testing.T) {
	c, path := driveStub(t, 200, "workbook bytes")
	got, err := c.DriveItemContent(context.Background(), "b!drive", "ITEM1", 1<<20)
	if err != nil || string(got) != "workbook bytes" {
		t.Fatalf("%q %v", got, err)
	}
	if !strings.Contains(*path, "/drives/b!drive/items/ITEM1/content") {
		t.Errorf("path = %q", *path)
	}
}

func TestAFileReadRefusedSaysWhichPermissionToAdd(t *testing.T) {
	c, _ := driveStub(t, 403, `{"error":{"code":"accessDenied","message":"no"}}`)
	_, err := c.DriveItemContent(context.Background(), "d", "i", 1<<20)
	if err == nil || !strings.Contains(err.Error(), "Sites.Selected") {
		t.Errorf("the error does not name the permission: %v", err)
	}
}

func TestAnOversizeFileIsAnErrorNotATruncatedWorkbook(t *testing.T) {
	c, _ := driveStub(t, 200, strings.Repeat("x", 100))
	if _, err := c.DriveItemContent(context.Background(), "d", "i", 50); err == nil {
		t.Error("a file over the limit was returned")
	}
	if _, err := c.DriveItemContent(context.Background(), "", "i", 50); err == nil {
		t.Error("an empty drive id was accepted")
	}
}
