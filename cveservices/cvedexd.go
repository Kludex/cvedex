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
	CVEID     string          `json:"cve_id"`
	Submitter string          `json:"submitter"`
	Record    json.RawMessage `json:"record"`
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

// AuditEntry is one request cvedexd served.
type AuditEntry struct {
	ID         int     `json:"id"`
	Time       string  `json:"ts"`
	Actor      *string `json:"actor"`
	ActorKind  *string `json:"actor_kind"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Status     int     `json:"status"`
	ProposalID *string `json:"proposal_id"`
}

// AuditFilter narrows the audit log. Empty fields match everything.
type AuditFilter struct {
	User string
	// Since is an ISO 8601 date or time.
	Since string
}

// Token is a cvedexd credential for a submitter. Kind is `user` or `agent`.
type Token struct {
	Kind  string `json:"kind"`
	Token string `json:"token"`
}

// Submitter is a cvedexd account that can reserve IDs and submit records for review, but has no
// CVE Services key.
type Submitter struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Token
}

// Review lists the records waiting for review on cvedexd. Only CNA users can.
func (c *Client) Review(ctx context.Context) ([]ReviewItem, error) {
	var out struct {
		CVEs []ReviewItem `json:"cves"`
	}
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/review", nil, nil, &out)
	return out.CVEs, err
}

// Approve publishes a record in review, upstream with the client's credentials, and returns it.
func (c *Client) Approve(ctx context.Context, id string) (json.RawMessage, error) {
	var out writeResult
	err := c.Do(ctx, http.MethodPost, "/api/cvedexd/cve/"+url.PathEscape(id)+"/approve", nil, nil, &out)
	return out.record(), err
}

// RequestChanges sends a record in review back to its submitter with a note.
func (c *Client) RequestChanges(ctx context.Context, id, note string) error {
	path := "/api/cvedexd/cve/" + url.PathEscape(id) + "/request-changes"
	return c.Do(ctx, http.MethodPost, path, nil, map[string]string{"note": note}, nil)
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

// Audit returns the newest audit entries first, up to 1000. Only CNA users can.
func (c *Client) Audit(ctx context.Context, filter AuditFilter) ([]AuditEntry, error) {
	query := url.Values{}
	if filter.User != "" {
		query.Set("user", filter.User)
	}
	if filter.Since != "" {
		query.Set("since", filter.Since)
	}
	var out struct {
		Audit []AuditEntry `json:"audit"`
	}
	err := c.Do(ctx, http.MethodGet, "/api/cvedexd/audit", query, nil, &out)
	return out.Audit, err
}

// AddSubmitter creates a submitter and returns it with its first `user` token. Only CNA users can.
func (c *Client) AddSubmitter(ctx context.Context, name string) (*Submitter, error) {
	var out Submitter
	err := c.Do(ctx, http.MethodPost, "/api/cvedexd/submitters", nil, map[string]string{"name": name}, &out)
	return &out, err
}

// NewToken issues a `user` or `agent` token for a submitter.
func (c *Client) NewToken(ctx context.Context, submitterID int, kind string) (*Token, error) {
	var out Token
	path := "/api/cvedexd/submitters/" + strconv.Itoa(submitterID) + "/tokens"
	err := c.Do(ctx, http.MethodPost, path, nil, map[string]string{"kind": kind}, &out)
	return &out, err
}
