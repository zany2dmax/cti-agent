package main

import (
	"fmt"
	"strings"
	"testing"
)

// msrc.microsoft.com/blog/feed began redirecting to a web page. For four days
// the lane logged "mismatched tag: line 124, column 158", which sent everyone
// looking for a bad byte in somebody's XML. A page is NOT A FEED, and the
// message says where to fix it.
func TestMSRCBlogPageIsNotAFeed(t *testing.T) {
	page := []byte("<!DOCTYPE html>\n<html lang=\"en-us\"><head><title>Blog MSRC</title></head><body><h1>MSRC Blog</h1></body></html>")
	var log strings.Builder
	items := parseFeed(page, "https://example.invalid/feed", func(f string, a ...any) { _, _ = fmt.Fprintf(&log, f, a...) })
	if len(items) != 0 || !strings.Contains(log.String(), "NOT A FEED") || !strings.Contains(log.String(), "feeds.txt") ||
		strings.Contains(log.String(), "mismatched") {
		t.Errorf("%d items, logged %q", len(items), log.String())
	}
	// The MSRC Update Guide RSS is served with a BOM: still a feed.
	feed := []byte("\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?><rss version=\"2.0\"><channel><item>" +
		"<title>Chromium: CVE-2026-1 Type Confusion</title><pubDate>Sun, 04 Oct 2026 02:13:15 -0700</pubDate></item></channel></rss>")
	if looksLikeHTML(feed) {
		t.Error("a BOM made a feed look like HTML")
	}
	if items := parseFeed(feed, "u", func(string, ...any) {}); len(items) != 1 || *items[0].Published != "2026-10-04T02:13:15-07:00" {
		t.Errorf("BOM feed: %+v", items)
	}
}
