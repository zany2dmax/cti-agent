package graph

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DriveItemContent downloads one file from a SharePoint or OneDrive drive by
// its drive and item ids, read-only.
//
// The fleet's Graph app registration needs permission to read that file as an
// APPLICATION: Sites.Selected with a read grant on the one site is the narrow
// way, Files.Read.All or Sites.Read.All the broad one. Without it Graph answers
// 403 and the error says which to add, since the mail permissions the lanes
// already hold do not reach files.
//
// maxBytes bounds the read; a file larger than that is an error, never a
// truncated workbook.
func (c *Client) DriveItemContent(ctx context.Context, driveID, itemID string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(driveID) == "" || strings.TrimSpace(itemID) == "" {
		return nil, fmt.Errorf("a drive id and an item id are both needed to read a file")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := c.graphBase + "/drives/" + url.PathEscape(driveID) + "/items/" + url.PathEscape(itemID) + "/content"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	// Graph answers with a redirect to a short-lived download URL on another
	// host; Go drops the Authorization header on that hop, which is what is wanted.
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the file: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("the file is larger than %d bytes - not reading it", maxBytes)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return body, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("graph refused to read the file (HTTP %d). The app registration needs an application "+
			"permission that reaches SharePoint files: Sites.Selected with a read grant on the site that holds it "+
			"(preferred), or Files.Read.All / Sites.Read.All, with admin consent. The mail permissions do not cover files",
			resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("graph found no file with that drive and item id (HTTP 404) - check the ids, " +
			"and that the file was not moved or recreated")
	}
	return nil, graphError(resp.StatusCode, body, endpoint)
}
