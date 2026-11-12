package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OldMessage is a message the mailbox cleanup's stale sweep considers: who
// it is, when it arrived, and whether a person flagged it. No body and no
// headers - the sweep moves mail by age alone, so it reads nothing it could
// be tempted to judge.
type OldMessage struct {
	ID               string
	Subject          string
	ReceivedDateTime time.Time
	// Flagged is a person's "I am dealing with this" - a flag that is set
	// (flagged) or done (complete). The sweep never moves one.
	Flagged bool
}

// OldMessages returns up to max messages in folder received BEFORE before,
// oldest first. The mailbox cleanup's stale sweep uses it for mail that has
// fallen out of every lane's window; the cap keeps a first run against a
// years-deep inbox to a bounded number of moves a day.
func (c *Client) OldMessages(ctx context.Context, mailbox, folder string, before time.Time, max int) ([]OldMessage, error) {
	if max <= 0 {
		return nil, nil
	}
	top := 50
	if max < top {
		top = max
	}
	params := []string{
		fmt.Sprintf("$top=%d", top),
		"$select=" + url.QueryEscape("id,subject,receivedDateTime,flag"),
		// $orderby has to name the $filter's property first, or Graph
		// refuses the query as too complex.
		"$orderby=" + url.QueryEscape("receivedDateTime asc"),
		"$filter=" + url.QueryEscape(fmt.Sprintf("receivedDateTime lt %s",
			before.UTC().Format(time.RFC3339))),
	}
	endpoint := fmt.Sprintf("%s/users/%s/mailFolders/%s/messages?%s", c.graphBase,
		url.PathEscape(mailbox), url.PathEscape(folder), strings.Join(params, "&"))

	var out []OldMessage
	for endpoint != "" && len(out) < max {
		body, err := c.get(ctx, endpoint, nil, maxPageBytes)
		if err != nil {
			return nil, err
		}
		var r struct {
			Value []struct {
				ID               string    `json:"id"`
				Subject          string    `json:"subject"`
				ReceivedDateTime time.Time `json:"receivedDateTime"`
				Flag             struct {
					FlagStatus string `json:"flagStatus"`
				} `json:"flag"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Value {
			if len(out) == max {
				break
			}
			// Anything but notFlagged counts: "complete" is a flag a person
			// set and then marked done, which is still a person's decision
			// about this message.
			st := strings.TrimSpace(m.Flag.FlagStatus)
			out = append(out, OldMessage{ID: m.ID, Subject: m.Subject,
				ReceivedDateTime: m.ReceivedDateTime,
				Flagged:          st != "" && !strings.EqualFold(st, "notFlagged")})
		}
		endpoint = r.NextLink
	}
	return out, nil
}

// ChildFolder is a mail folder under a well-known one, found by its name.
//
// A value of this type comes only from FindChildFolder or CreateChildFolder,
// so MoveToChildFolder cannot be pointed at an arbitrary folder ID: the
// destination is always a folder this package looked up by name under the
// folder the lane reads, never one read from a message or a config value.
type ChildFolder struct {
	id   string
	Name string
}

// FindChildFolder looks for the folder called name directly under parent
// (a well-known folder name such as "inbox"). ok is false when there is none.
func (c *Client) FindChildFolder(ctx context.Context, mailbox, parent, name string) (ChildFolder, bool, error) {
	if err := ValidFolderName(name); err != nil {
		return ChildFolder{}, false, err
	}
	// OData quotes a string by doubling any single quote in it.
	filter := fmt.Sprintf("displayName eq '%s'", strings.ReplaceAll(name, "'", "''"))
	endpoint := fmt.Sprintf("%s/users/%s/mailFolders/%s/childFolders?$select=id,displayName&$filter=%s",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(parent), url.QueryEscape(filter))
	body, err := c.get(ctx, endpoint, nil, 1<<20)
	if err != nil {
		return ChildFolder{}, false, err
	}
	var r struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return ChildFolder{}, false, err
	}
	for _, f := range r.Value {
		// Graph's eq on displayName is case-insensitive; so is Outlook.
		if strings.EqualFold(f.DisplayName, name) && f.ID != "" {
			return ChildFolder{id: f.ID, Name: f.DisplayName}, true, nil
		}
	}
	return ChildFolder{}, false, nil
}

// CreateChildFolder makes the folder called name under parent.
func (c *Client) CreateChildFolder(ctx context.Context, mailbox, parent, name string) (ChildFolder, error) {
	if err := ValidFolderName(name); err != nil {
		return ChildFolder{}, err
	}
	tok, err := c.token(ctx)
	if err != nil {
		return ChildFolder{}, err
	}
	endpoint := fmt.Sprintf("%s/users/%s/mailFolders/%s/childFolders",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(parent))
	payload, err := json.Marshal(map[string]any{"displayName": name, "isHidden": false})
	if err != nil {
		return ChildFolder{}, err
	}
	body, status, err := c.post(ctx, tok, endpoint, payload)
	if err != nil {
		return ChildFolder{}, err
	}
	if status < 200 || status > 299 {
		return ChildFolder{}, moveError(status, body, mailbox, Folder("folder "+name))
	}
	var f struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &f); err != nil || f.ID == "" {
		return ChildFolder{}, fmt.Errorf("creating folder %q: Graph returned no folder id", name)
	}
	return ChildFolder{id: f.ID, Name: f.DisplayName}, nil
}

// MoveToChildFolder moves one message into a folder FindChildFolder or
// CreateChildFolder returned, and returns its new ID.
func (c *Client) MoveToChildFolder(ctx context.Context, mailbox, messageID string, dest ChildFolder) (string, error) {
	if dest.id == "" {
		return "", fmt.Errorf("MoveToChildFolder: no folder - look it up with FindChildFolder first")
	}
	if strings.TrimSpace(mailbox) == "" || strings.TrimSpace(messageID) == "" {
		return "", fmt.Errorf("MoveToChildFolder: mailbox and messageID are both required")
	}
	tok, err := c.token(ctx)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/users/%s/messages/%s/move",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(messageID))
	payload, err := json.Marshal(map[string]string{"destinationId": dest.id})
	if err != nil {
		return "", err
	}
	body, status, err := c.post(ctx, tok, endpoint, payload)
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", moveError(status, body, mailbox, Folder(dest.Name))
	}
	var moved struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &moved) // a 2xx is a move, parsed or not
	return moved.ID, nil
}

// ValidFolderName refuses a folder name that is empty, long, or has a path
// separator or control character in it: it is a setting, and it becomes a
// folder in a shared mailbox.
func ValidFolderName(name string) error {
	n := strings.TrimSpace(name)
	switch {
	case n == "":
		return fmt.Errorf("folder name is empty")
	case n != name:
		return fmt.Errorf("folder name %q has leading or trailing spaces", name)
	case len(n) > 64:
		return fmt.Errorf("folder name is longer than 64 characters")
	case strings.ContainsAny(n, "/\\"):
		return fmt.Errorf("folder name %q has a path separator in it", name)
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("folder name has a control character in it")
		}
	}
	return nil
}

func (c *Client) post(ctx context.Context, tok, endpoint string, payload []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
