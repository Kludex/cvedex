// Package cveservices is a client for CVE Services, the API that CNAs use to reserve CVE IDs and
// publish CVE records. It speaks the same API to MITRE and to a cvedexd policy server; the base
// URL is the only difference.
package cveservices

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

// ProductionURL is MITRE's CVE Services. Records published here are public.
const ProductionURL = "https://cveawg.mitre.org"

// TestURL is MITRE's test instance, for trying things without publishing real records.
const TestURL = "https://cveawg-test.mitre.org"

// Credentials identify a CVE Services user: the CNA's short name, the username and its API key.
type Credentials struct {
	URL  string `json:"url"`
	Org  string `json:"org"`
	User string `json:"user"`
	Key  string `json:"key"`
}

// Client calls CVE Services with one set of credentials.
type Client struct {
	Credentials Credentials
	HTTP        *http.Client
}

// New returns a client that never follows redirects, so the API key is only sent to URL.
func New(creds Credentials) *Client {
	if creds.URL == "" {
		creds.URL = ProductionURL
	}
	return &Client{Credentials: creds, HTTP: &http.Client{
		Timeout: time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// Error is a response with a status of 300 or more. Code and Message come from the CVE Services
// error body when there is one.
type Error struct {
	Status  int             `json:"-"`
	Code    string          `json:"error"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
	// Body is the response body as received.
	Body []byte `json:"-"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d %s", e.Status, http.StatusText(e.Status))
	}
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s (%s)", e.Message, e.Code)
}

// PendingApproval is returned when cvedexd holds a write made with an agent token until the
// submitter approves it.
type PendingApproval struct {
	ProposalID string `json:"proposal_id"`
}

func (p *PendingApproval) Error() string {
	return "waiting for approval as proposal " + p.ProposalID
}

const maxBody = 16 << 20

// Do sends one request and decodes a JSON response into out, which may be nil. A status of 300
// or more returns an *Error, and a cvedexd proposal returns a *PendingApproval.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(data)
	}
	target := strings.TrimRight(c.Credentials.URL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "cvedex")
	req.Header.Set("CVE-API-ORG", c.Credentials.Org)
	req.Header.Set("CVE-API-USER", c.Credentials.User)
	req.Header.Set("CVE-API-KEY", c.Credentials.Key)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		e := &Error{Status: resp.StatusCode, Body: data}
		_ = json.Unmarshal(data, e)
		return e
	}
	if resp.StatusCode == http.StatusAccepted {
		var pending PendingApproval
		if json.Unmarshal(data, &pending) == nil && pending.ProposalID != "" {
			return &pending
		}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
