package cveservices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// Health is what `GET /api/health-check` reports. CVE Services answers with an empty body;
// cvedexd names itself.
type Health struct {
	Server  string `json:"server"`
	Version string `json:"version"`
}

// IsCvedexd reports whether the server is a cvedexd policy server.
func (h Health) IsCvedexd() bool {
	return h.Server == "cvedexd"
}

// Health checks that the server is up and says which kind it is. It needs no credentials.
func (c *Client) Health(ctx context.Context) (Health, error) {
	var health Health
	err := c.Do(ctx, http.MethodGet, "/api/health-check", nil, nil, &health)
	return health, err
}

// ReviewItem is a record a submitter sent for review on cvedexd.
type ReviewItem struct {
	CVEID     string `json:"cve_id"`
	Submitter string `json:"submitter"`
	// Action is `publish`, for a new or updated record, or `reject`.
	Action string `json:"action"`
	// Revision is what Approve and RequestChanges need, so a record that changed since it was
	// read is never approved by mistake.
	Revision int             `json:"revision"`
	Record   json.RawMessage `json:"record"`
	// Previous is the revision before this one, and Published the one CVE Services has, when
	// there are.
	Previous  json.RawMessage `json:"previous"`
	Published json.RawMessage `json:"published"`
	UpdatedAt string          `json:"updated_at"`
}

// Proposal is a write an agent token made on cvedexd, held for its submitter to approve.
type Proposal struct {
	ID        string  `json:"id"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Body      *string `json:"body"`
	CreatedAt string  `json:"created_at"`
}

// AuditEntry is one request a signed-in caller made to cvedexd.
type AuditEntry struct {
	ID        int    `json:"id"`
	Time      string `json:"ts"`
	Actor     string `json:"actor"`
	ActorKind string `json:"actor_kind"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	// Status is nil when the request never finished, so its outcome is unknown.
	Status     *int    `json:"status"`
	ProposalID *string `json:"proposal_id"`
}

// AuditFilter narrows the audit log. Empty fields match everything.
type AuditFilter struct {
	User string
	// Since is an ISO 8601 date or time.
	Since string
	// Before is an entry ID: only older entries are returned. AuditPage.Next is the one to pass for
	// the next page.
	Before int
}

// AuditPage is up to 500 audit entries, newest first.
type AuditPage struct {
	Entries []AuditEntry `json:"audit"`
	// Next is the AuditFilter.Before of the next page, or nil on the last one.
	Next *int `json:"next"`
}

// Token is a cvedexd credential for a submitter. Kind is `user` or `agent`.
type Token struct {
	ID    int    `json:"token_id"`
	Kind  string `json:"kind"`
	Token string `json:"token"`
}

// TokenInfo describes a token without its secret.
type TokenInfo struct {
	ID         int     `json:"id"`
	Kind       string  `json:"kind"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	RevokedAt  *string `json:"revoked_at"`
}

// NewSubmitter is a submitter just created, with its first `user` token.
type NewSubmitter struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Token
}

// Submitter is a cvedexd account that can reserve IDs and submit records for review, but has no
// CVE Services key.
type Submitter struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	DisabledAt *string `json:"disabled_at"`
	// OpenIDs counts the submitter's IDs that are not published or rejected.
	OpenIDs int `json:"open_ids"`
	// Tokens counts the submitter's tokens that are not revoked.
	Tokens int `json:"tokens"`
}

// Review lists the records waiting for review on cvedexd. Only CNA users can.
func (c *Client) Review(ctx context.Context) ([]ReviewItem, error) {
	var out struct {
		CVEs []ReviewItem `json:"cves"`
	}
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/review", nil, nil, &out)
	return out.CVEs, err
}

// Approve publishes or rejects a record in review, upstream with the client's credentials, and
// returns it. revision is the ReviewItem.Revision the reviewer read.
func (c *Client) Approve(ctx context.Context, id string, revision int) (json.RawMessage, error) {
	var body json.RawMessage
	path := "/api/cvedexd/cve/" + url.PathEscape(id) + "/approve"
	err := c.Do(ctx, http.MethodPost, path, nil, map[string]int{"revision": revision}, &body)
	return written(body), err
}

// RequestChanges sends a record in review back to its submitter with a note. revision is the
// ReviewItem.Revision the reviewer read.
func (c *Client) RequestChanges(ctx context.Context, id string, revision int, note string) error {
	path := "/api/cvedexd/cve/" + url.PathEscape(id) + "/request-changes"
	return c.Do(ctx, http.MethodPost, path, nil, map[string]any{"note": note, "revision": revision}, nil)
}

// Proposals lists the pending proposals of the client's submitter account.
func (c *Client) Proposals(ctx context.Context) ([]Proposal, error) {
	var out struct {
		Proposals []Proposal `json:"proposals"`
	}
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/proposals", nil, nil, &out)
	return out.Proposals, err
}

// ApproveProposal replays a proposal as the submitter and returns the response body.
func (c *Client) ApproveProposal(ctx context.Context, id string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.Do(ctx, http.MethodPost, "/api/cvedexd/proposals/"+url.PathEscape(id)+"/approve", nil, nil, &out)
	return out, err
}

// DenyProposal discards a proposal.
func (c *Client) DenyProposal(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodPost, "/api/cvedexd/proposals/"+url.PathEscape(id)+"/deny", nil, nil, nil)
}

// Audit returns a page of audit entries, newest first. Only CNA users can.
func (c *Client) Audit(ctx context.Context, filter AuditFilter) (*AuditPage, error) {
	query := url.Values{}
	if filter.User != "" {
		query.Set("user", filter.User)
	}
	if filter.Since != "" {
		query.Set("since", filter.Since)
	}
	if filter.Before != 0 {
		query.Set("before", strconv.Itoa(filter.Before))
	}
	var out AuditPage
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/audit", query, nil, &out)
	return &out, err
}

// Submitters lists every submitter. Only CNA users can.
func (c *Client) Submitters(ctx context.Context) ([]Submitter, error) {
	var out struct {
		Submitters []Submitter `json:"submitters"`
	}
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/submitters", nil, nil, &out)
	return out.Submitters, err
}

// AddSubmitter creates a submitter and returns it with its first `user` token. Only CNA users can.
func (c *Client) AddSubmitter(ctx context.Context, name string) (*NewSubmitter, error) {
	var out NewSubmitter
	err := c.Do(ctx, http.MethodPost, "/api/cvedexd/submitters", nil, map[string]string{"name": name}, &out)
	return &out, err
}

// SetSubmitterDisabled disables a submitter, which stops all its tokens and denies its pending
// proposals, or enables it again. Only CNA users can.
func (c *Client) SetSubmitterDisabled(ctx context.Context, submitterID int, disabled bool) (*Submitter, error) {
	change := "/enable"
	if disabled {
		change = "/disable"
	}
	var out Submitter
	err := c.Do(ctx, http.MethodPost, "/api/cvedexd/submitters/"+strconv.Itoa(submitterID)+change, nil, nil, &out)
	return &out, err
}

// Tokens lists a submitter's tokens, revoked ones included.
func (c *Client) Tokens(ctx context.Context, submitterID int) ([]TokenInfo, error) {
	var out struct {
		Tokens []TokenInfo `json:"tokens"`
	}
	path := "/api/cvedexd/submitters/" + strconv.Itoa(submitterID) + "/tokens"
	err := c.Do(ctx, http.MethodGet, path, nil, nil, &out)
	return out.Tokens, err
}

// NewToken issues a `user` or `agent` token for a submitter.
func (c *Client) NewToken(ctx context.Context, submitterID int, kind string) (*Token, error) {
	var out Token
	path := "/api/cvedexd/submitters/" + strconv.Itoa(submitterID) + "/tokens"
	err := c.Do(ctx, http.MethodPost, path, nil, map[string]string{"kind": kind}, &out)
	return &out, err
}

// RevokeToken stops a token at once and denies the proposals it made that are still pending. CNA
// users can revoke any token, submitters their own.
func (c *Client) RevokeToken(ctx context.Context, tokenID int) (*TokenInfo, error) {
	var out TokenInfo
	err := c.Do(ctx, http.MethodDelete, "/api/cvedexd/tokens/"+strconv.Itoa(tokenID), nil, nil, &out)
	return &out, err
}
