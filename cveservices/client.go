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
	"strconv"
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
	Key  string `json:"key,omitempty"`
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

const (
	maxBody = 16 << 20
	// retries is how many times a rate-limited request is sent again.
	retries = 3
)

// Do sends one request and decodes a JSON response into out, which may be nil. A status of 300
// or more returns an *Error, and a cvedexd proposal returns a *PendingApproval. A rate-limited
// request is sent again up to three times, after the wait the server asks for, of a minute at most.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	target := strings.TrimRight(c.Credentials.URL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	resp, err := c.send(ctx, method, target, payload)
	for attempt := 0; err == nil && resp.status == http.StatusTooManyRequests && attempt < retries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(resp.retryAfter, time.Minute)):
		}
		resp, err = c.send(ctx, method, target, payload)
	}
	if err != nil {
		return err
	}
	data := resp.body
	if resp.status >= http.StatusMultipleChoices {
		e := &Error{Status: resp.status, Body: data}
		_ = json.Unmarshal(data, e)
		return e
	}
	if resp.status == http.StatusAccepted {
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

type response struct {
	status     int
	body       []byte
	retryAfter time.Duration
}

func (c *Client) send(ctx context.Context, method, target string, payload []byte) (response, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return response{}, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "cvedex")
	req.Header.Set("CVE-API-ORG", c.Credentials.Org)
	req.Header.Set("CVE-API-USER", c.Credentials.User)
	req.Header.Set("CVE-API-KEY", c.Credentials.Key)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return response{}, err
	}
	wait, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil {
		wait = 1
	}
	return response{resp.StatusCode, data, time.Duration(wait) * time.Second}, nil
}
