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
	}
}

func (c *Client) token(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.tenantID)
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

func (c *Client) RecentMessages(ctx context.Context, mailbox, folder string, since time.Time) ([]Message, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}

	filter := fmt.Sprintf("receivedDateTime ge %s", since.UTC().Format(time.RFC3339))
	selectFields := "id,subject,receivedDateTime,from,body"
	endpoint := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/mailFolders/%s/messages?$top=50&$select=%s&$orderby=receivedDateTime desc&$filter=%s",
		url.PathEscape(mailbox),
		url.PathEscape(folder),
		url.QueryEscape(selectFields),
		url.QueryEscape(filter),
	)

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
			return nil, fmt.Errorf("graph messages request failed: HTTP %d: %s", resp.StatusCode, string(body))
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
