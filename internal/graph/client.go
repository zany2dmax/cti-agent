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

type Client struct {
	tenantID     string
	clientID     string
	clientSecret string
	http         *http.Client

	// Endpoints are fields rather than constants so tests can point them at a
	// local server. Without this the whole client was untestable without
	// network access, which is how an unescaped space in $orderby shipped.
	tokenEndpoint string // full URL; defaults to the Entra v2 token endpoint
	graphBase     string // scheme+host, no trailing slash
}

type Message struct {
	ID               string    `json:"id"`
	Subject          string    `json:"subject"`
	ReceivedDateTime time.Time `json:"receivedDateTime"`
	From             string
	BodyText         string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type messagesResponse struct {
	Value []struct {
		ID               string    `json:"id"`
		Subject          string    `json:"subject"`
		ReceivedDateTime time.Time `json:"receivedDateTime"`
		From             struct {
			EmailAddress struct {
				Name    string `json:"name"`
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"from"`
		Body struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
	} `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

func New(tenantID, clientID, clientSecret string) *Client {
	return &Client{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 60 * time.Second},
		tokenEndpoint: fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
		graphBase: "https://graph.microsoft.com/v1.0",
	}
}

func (c *Client) token(ctx context.Context) (string, error) {
	endpoint := c.tokenEndpoint
	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", "https://graph.microsoft.com/.default")
	form.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read graph token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("graph token request failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("graph token response did not include access_token")
	}
	return tr.AccessToken, nil
}

// messagesURL builds the first-page request URL for a mailbox folder.
//
// Extracted so it can be tested without a network call. It exists because an
// unescaped space in $orderby shipped once: every OData *value* must be
// escaped, or the space lands in the HTTP request line and the edge rejects
// the request with an HTML "Bad Request" page before Graph's API layer sees
// it. That failure does not look like a Graph error, so it costs real time.
//
// The "$" prefixes stay literal rather than going through
// url.Values.Encode(), which would percent-encode them to %24. Graph accepts
// %24, but literal "$" matches its documentation and error messages, which
// keeps these URLs greppable against the docs.
func messagesURL(mailbox, folder string, since time.Time) string {
	return messagesURLBase("https://graph.microsoft.com/v1.0", mailbox, folder, since)
}

func messagesURLBase(base, mailbox, folder string, since time.Time) string {
	filter := fmt.Sprintf("receivedDateTime ge %s", since.UTC().Format(time.RFC3339))
	selectFields := "id,subject,receivedDateTime,from,body"

	params := []string{
		"$top=50",
		"$select=" + url.QueryEscape(selectFields),
		"$orderby=" + url.QueryEscape("receivedDateTime desc"),
		"$filter=" + url.QueryEscape(filter),
	}
	return fmt.Sprintf("%s/users/%s/mailFolders/%s/messages?%s",
		base,
		url.PathEscape(mailbox),
		url.PathEscape(folder),
		strings.Join(params, "&"),
	)
}

// graphError turns a failed response into something actionable.
//
// Graph reports its own errors as JSON. An HTML body means the request never
// reached Graph - it was rejected by the edge for being malformed - so saying
// so directly saves a long detour through permissions and mailbox settings
// that are not the problem.
func graphError(status int, body []byte, endpoint string) error {
	trimmed := strings.TrimSpace(string(body))

	if strings.HasPrefix(trimmed, "<") {
		return fmt.Errorf("graph request was rejected before reaching the API "+
			"(HTTP %d, HTML response). This means a malformed URL, almost always "+
			"an unescaped character in an OData query parameter such as a space "+
			"in $orderby or $filter.\nrequest: %s",
			status, endpoint)
	}

	var ge struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &ge); err == nil && ge.Error.Code != "" {
		hint := ""
		switch ge.Error.Code {
		case "ErrorAccessDenied", "Authorization_RequestDenied", "ErrorItemNotFound":
			hint = "\nhint: check that Mail.Read is granted as an APPLICATION " +
				"permission with admin consent, and that any Application Access " +
				"Policy includes this mailbox."
		case "ResourceNotFound", "ErrorInvalidUser", "MailboxNotEnabledForRESTAPI":
			hint = "\nhint: check GRAPH_MAILBOX is a real, licensed mailbox, and " +
				"that GRAPH_FOLDER names an existing folder."
		case "ErrorInvalidProperty", "BadRequest":
			hint = "\nhint: the OData query was understood but rejected - check " +
				"$select field names and the $filter datetime format."
		}
		return fmt.Errorf("graph messages request failed: HTTP %d %s: %s%s",
			status, ge.Error.Code, ge.Error.Message, hint)
	}

	if len(trimmed) > 800 {
		trimmed = trimmed[:800] + "..."
	}
	return fmt.Errorf("graph messages request failed: HTTP %d: %s", status, trimmed)
}

func (c *Client) RecentMessages(ctx context.Context, mailbox, folder string, since time.Time) ([]Message, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := messagesURLBase(c.graphBase, mailbox, folder, since)

	var all []Message
	for endpoint != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Prefer", `outlook.body-content-type="text"`)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("failed to read graph messages response: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close graph messages response body: %w", closeErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, graphError(resp.StatusCode, body, endpoint)
		}

		var mr messagesResponse
		if err := json.Unmarshal(body, &mr); err != nil {
			return nil, err
		}
		for _, m := range mr.Value {
			from := strings.TrimSpace(m.From.EmailAddress.Address)
			if m.From.EmailAddress.Name != "" {
				from = fmt.Sprintf("%s <%s>", m.From.EmailAddress.Name, m.From.EmailAddress.Address)
			}
			all = append(all, Message{
				ID:               m.ID,
				Subject:          m.Subject,
				ReceivedDateTime: m.ReceivedDateTime,
				From:             from,
				BodyText:         m.Body.Content,
			})
		}
		endpoint = mr.NextLink
	}
	return all, nil
}

// ── sending ─────────────────────────────────────────────────────────────────

// SendMailRequest is one outbound message.
type SendMailRequest struct {
	From    string   // the mailbox to send AS; needs Mail.Send on the app
	To      []string // recipients
	Subject string
	HTML    string // body, contentType HTML
	// HighImportance flags the message. Reserved for genuine Sev5 alerts: a
	// system that marks everything urgent has marked nothing urgent.
	HighImportance bool
}

type sendMailPayload struct {
	Message struct {
		Subject string `json:"subject"`
		Body    struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ToRecipients []recipient `json:"toRecipients"`
		Importance   string      `json:"importance"`
	} `json:"message"`
	SaveToSentItems bool `json:"saveToSentItems"`
}

type recipient struct {
	EmailAddress struct {
		Address string `json:"address"`
	} `json:"emailAddress"`
}

// SendMail sends one message as the given mailbox via Graph sendMail.
//
// This reuses the same app registration and token path the mailbox reader
// uses, so the only extra requirement is the Mail.Send application permission
// with admin consent.
//
// It returns the Graph request-id on success. sendMail answers 202 with an
// empty body, so there is no message id to report - request-id is what
// Microsoft support asks for when a message goes missing.
func (c *Client) SendMail(ctx context.Context, req SendMailRequest) (string, error) {
	if req.From == "" {
		return "", fmt.Errorf("SendMail: From is required (the sending mailbox)")
	}
	if len(req.To) == 0 {
		// No default recipient, deliberately. A hardcoded address is a
		// mis-send waiting to happen on someone else's tenant.
		return "", fmt.Errorf("SendMail: at least one recipient is required")
	}
	if req.Subject == "" {
		return "", fmt.Errorf("SendMail: Subject is required")
	}

	tok, err := c.token(ctx)
	if err != nil {
		return "", err
	}

	var p sendMailPayload
	p.Message.Subject = req.Subject
	p.Message.Body.ContentType = "HTML"
	p.Message.Body.Content = req.HTML
	p.Message.Importance = "normal"
	if req.HighImportance {
		p.Message.Importance = "high"
	}
	for _, addr := range req.To {
		var r recipient
		r.EmailAddress.Address = addr
		p.Message.ToRecipients = append(p.Message.ToRecipients, r)
	}
	p.SaveToSentItems = true

	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/users/%s/sendMail",
		c.graphBase, url.PathEscape(req.From))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+tok)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read sendMail response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", sendMailError(resp.StatusCode, respBody, req.From)
	}

	reqID := resp.Header.Get("request-id")
	if reqID == "" {
		reqID = resp.Header.Get("client-request-id")
	}
	return reqID, nil
}

// sendMailError annotates the failures that actually happen in practice,
// because "403 Forbidden" on its own sends people to the wrong place.
func sendMailError(status int, body []byte, mailbox string) error {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 600 {
		trimmed = trimmed[:600] + "..."
	}
	switch {
	case status == 403 && strings.Contains(trimmed, "MailboxNotEnabledForRESTAPI"):
		return fmt.Errorf("sendMail 403: %s is not a REST-enabled mailbox "+
			"(shared mailboxes need a license, or it is on-prem): %s", mailbox, trimmed)
	case status == 403:
		return fmt.Errorf("sendMail 403: the app registration is probably missing "+
			"Mail.Send as an APPLICATION permission, or admin consent was never "+
			"granted, or an Application Access Policy excludes %s: %s", mailbox, trimmed)
	case status == 404:
		return fmt.Errorf("sendMail 404: mailbox %s not found - check the address "+
			"and that it is a real mailbox, not a distribution group: %s", mailbox, trimmed)
	default:
		return fmt.Errorf("sendMail failed: HTTP %d: %s", status, trimmed)
	}
}
