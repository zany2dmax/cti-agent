package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AddressedMessage is a message with the people it was sent to, for a lane that
// owns mail by the address it was written to (the supplier-request lane) rather
// than by who sent it or what it says.
type AddressedMessage struct {
	ID             string
	ConversationID string
	Subject        string
	// From is the sender's address alone.
	From     string
	FromName string
	// To and Cc are addresses alone. Bcc is not read: a copy the sender hid is
	// not mail addressed to this mailbox's list.
	To       []string
	Cc       []string
	Received time.Time
	// BodyText is Graph's plain-text rendering of the body.
	BodyText       string
	HasAttachments bool
}

type addressedResponse struct {
	Value []struct {
		ID               string    `json:"id"`
		ConversationID   string    `json:"conversationId"`
		Subject          string    `json:"subject"`
		ReceivedDateTime time.Time `json:"receivedDateTime"`
		HasAttachments   bool      `json:"hasAttachments"`
		From             struct {
			EmailAddress struct {
				Name    string `json:"name"`
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"from"`
		ToRecipients []recipientJSON `json:"toRecipients"`
		CcRecipients []recipientJSON `json:"ccRecipients"`
		Body         struct {
			Content string `json:"content"`
		} `json:"body"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type recipientJSON struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

func addresses(rs []recipientJSON) []string {
	var out []string
	for _, r := range rs {
		if a := strings.TrimSpace(r.EmailAddress.Address); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func containsAddress(list []string, addr string) bool {
	for _, a := range list {
		if sameAddress(a, addr) {
			return true
		}
	}
	return false
}

// get does one authorized GET and returns the body, or graphError for a
// non-2xx answer.
func (c *Client) get(ctx context.Context, endpoint string, header map[string]string, maxBytes int64) ([]byte, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the graph response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("the graph response is larger than %d bytes - not reading it", maxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, graphError(resp.StatusCode, body, endpoint)
	}
	return body, nil
}

// maxPageBytes bounds one page of message listings, whose bodies can be large.
const maxPageBytes = 64 << 20

// MessagesAddressedTo reads the messages received since a time in one folder
// and returns those with the address in To or Cc, newest first as Graph gives
// them. The match is done here, by address and ignoring case, rather than in
// the query: a server-side filter on a recipient collection is the kind of
// query Graph is picky about, and a mailbox this size does not need it.
//
// Read-only. It never moves or marks a message.
func (c *Client) MessagesAddressedTo(ctx context.Context, mailbox, folder, address string, since time.Time) ([]AddressedMessage, error) {
	if strings.TrimSpace(address) == "" {
		return nil, fmt.Errorf("no address to look for: an unset address means the lane does nothing")
	}
	selectFields := "id,conversationId,subject,receivedDateTime,from,toRecipients,ccRecipients,body,hasAttachments"
	params := []string{
		"$top=50",
		"$select=" + url.QueryEscape(selectFields),
		"$orderby=" + url.QueryEscape("receivedDateTime desc"),
		"$filter=" + url.QueryEscape(fmt.Sprintf("receivedDateTime ge %s", since.UTC().Format(time.RFC3339))),
	}
	endpoint := fmt.Sprintf("%s/users/%s/mailFolders/%s/messages?%s",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(folder), strings.Join(params, "&"))

	var out []AddressedMessage
	for endpoint != "" {
		body, err := c.get(ctx, endpoint, map[string]string{"Prefer": `outlook.body-content-type="text"`}, maxPageBytes)
		if err != nil {
			return nil, err
		}
		var r addressedResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, m := range r.Value {
			to, cc := addresses(m.ToRecipients), addresses(m.CcRecipients)
			if !containsAddress(to, address) && !containsAddress(cc, address) {
				continue
			}
			out = append(out, AddressedMessage{
				ID: m.ID, ConversationID: m.ConversationID, Subject: m.Subject,
				From: strings.TrimSpace(m.From.EmailAddress.Address), FromName: m.From.EmailAddress.Name,
				To: to, Cc: cc, Received: m.ReceivedDateTime,
				BodyText: m.Body.Content, HasAttachments: m.HasAttachments,
			})
		}
		endpoint = r.NextLink
	}
	return out, nil
}

// AttachmentInfo describes one attachment without its content: the lane decides
// from this whether a file is one it may open.
type AttachmentInfo struct {
	ID          string
	Name        string
	ContentType string
	Size        int64
	Inline      bool
	// IsFile is false for an item attachment (a whole message) or a link
	// attachment, neither of which has file bytes to read.
	IsFile bool
}

// Attachments lists a message's attachments by name, type and size only. It
// never asks for content, so listing is safe whatever the files are.
func (c *Client) Attachments(ctx context.Context, mailbox, messageID string) ([]AttachmentInfo, error) {
	endpoint := fmt.Sprintf("%s/users/%s/messages/%s/attachments?$select=%s",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(messageID),
		url.QueryEscape("id,name,contentType,size,isInline"))
	var out []AttachmentInfo
	for endpoint != "" {
		body, err := c.get(ctx, endpoint, nil, maxPageBytes)
		if err != nil {
			return nil, err
		}
		var r struct {
			Value []struct {
				Type        string `json:"@odata.type"`
				ID          string `json:"id"`
				Name        string `json:"name"`
				ContentType string `json:"contentType"`
				Size        int64  `json:"size"`
				IsInline    bool   `json:"isInline"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, a := range r.Value {
			out = append(out, AttachmentInfo{
				ID: a.ID, Name: a.Name, ContentType: a.ContentType, Size: a.Size,
				Inline: a.IsInline, IsFile: strings.HasSuffix(a.Type, "fileAttachment"),
			})
		}
		endpoint = r.NextLink
	}
	return out, nil
}

// AttachmentContent downloads one attachment's bytes. A caller must decide the
// file is one it may open BEFORE calling this: the supplier lane does so with
// supplier.Policy, and never opens the tax and bank forms. maxBytes bounds the
// read; a larger file is an error, never a truncated one.
func (c *Client) AttachmentContent(ctx context.Context, mailbox, messageID, attachmentID string, maxBytes int64) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/users/%s/messages/%s/attachments/%s/$value",
		c.graphBase, url.PathEscape(mailbox), url.PathEscape(messageID), url.PathEscape(attachmentID))
	return c.get(ctx, endpoint, nil, maxBytes)
}
