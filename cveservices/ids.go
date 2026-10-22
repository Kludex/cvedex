package cveservices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// CVE ID states.
const (
	StateReserved  = "RESERVED"
	StatePublished = "PUBLISHED"
	StateRejected  = "REJECTED"
)

// CVEID is one entry of the org's CVE IDs.
type CVEID struct {
	ID          string      `json:"cve_id"`
	Year        string      `json:"cve_year"`
	State       string      `json:"state"`
	OwningCNA   string      `json:"owning_cna"`
	RequestedBy RequestedBy `json:"requested_by"`
	Reserved    time.Time   `json:"reserved"`
	// Cvedexd is set by a cvedexd server on the IDs a submitter reserved through it.
	Cvedexd *LocalState `json:"cvedexd,omitempty"`
}

// RequestedBy is who reserved a CVE ID.
type RequestedBy struct {
	CNA  string `json:"cna"`
	User string `json:"user"`
}

// LocalState is where a submitter's CVE ID is in cvedexd's review flow.
type LocalState struct {
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
}

// ReserveOptions says how many IDs to reserve and for which year.
type ReserveOptions struct {
	Year  int
	Count int
	// Sequential asks for consecutive IDs when Count is more than one.
	Sequential bool
}

// Reserve reserves CVE IDs for the client's org.
func (c *Client) Reserve(ctx context.Context, opts ReserveOptions) ([]CVEID, error) {
	count := max(opts.Count, 1)
	query := url.Values{
		"amount":     {strconv.Itoa(count)},
		"cve_year":   {strconv.Itoa(opts.Year)},
		"short_name": {c.Credentials.Org},
	}
	if count > 1 {
		batch := "nonsequential"
		if opts.Sequential {
			batch = "sequential"
		}
		query.Set("batch_type", batch)
	}
	var out struct {
		CVEIDs []CVEID `json:"cve_ids"`
	}
	err := c.Do(ctx, http.MethodPost, "/api/cve-id", query, nil, &out)
	return out.CVEIDs, err
}

// ListIDs returns every CVE ID of the org in state, or in any state when state is empty. It
// follows pagination.
func (c *Client) ListIDs(ctx context.Context, state string) ([]CVEID, error) {
	var ids []CVEID
	query := url.Values{}
	if state != "" {
		query.Set("state", state)
	}
	for {
		var page struct {
			CVEIDs   []CVEID `json:"cve_ids"`
			NextPage *int    `json:"nextPage"`
		}
		if err := c.Do(ctx, http.MethodGet, "/api/cve-id", query, nil, &page); err != nil {
			return nil, err
		}
		ids = append(ids, page.CVEIDs...)
		if page.NextPage == nil {
			return ids, nil
		}
		query.Set("page", strconv.Itoa(*page.NextPage))
	}
}

// Record returns a CVE record as JSON 5.x. Records are passed through as received; render them
// with your own types.
func (c *Client) Record(ctx context.Context, id string) (json.RawMessage, error) {
	var record json.RawMessage
	err := c.Do(ctx, http.MethodGet, "/api/cve/"+url.PathEscape(id), nil, nil, &record)
	return record, err
}

// Publish publishes the CNA container cna as the record of a reserved ID and returns the record.
func (c *Client) Publish(ctx context.Context, id string, cna json.RawMessage) (json.RawMessage, error) {
	return c.writeRecord(ctx, http.MethodPost, "/api/cve/"+url.PathEscape(id)+"/cna", cna)
}

// Update replaces the CNA container of a published record and returns the record.
func (c *Client) Update(ctx context.Context, id string, cna json.RawMessage) (json.RawMessage, error) {
	return c.writeRecord(ctx, http.MethodPut, "/api/cve/"+url.PathEscape(id)+"/cna", cna)
}

// Reject rejects a CVE ID. cna holds `rejectedReasons` and optionally `replacedBy`.
func (c *Client) Reject(ctx context.Context, id string, cna json.RawMessage) (json.RawMessage, error) {
	return c.writeRecord(ctx, http.MethodPost, "/api/cve/"+url.PathEscape(id)+"/reject", cna)
}

func (c *Client) writeRecord(ctx context.Context, method, path string, cna json.RawMessage) (json.RawMessage, error) {
	var body json.RawMessage
	err := c.Do(ctx, method, path, nil, map[string]json.RawMessage{"cnaContainer": cna}, &body)
	return written(body), err
}

// written picks the record out of a write's response: under `created` for a publish or reject and
// `updated` for an update. cvedexd answers a submitter with {message, state: "in_review"} instead,
// returned as is.
func written(body json.RawMessage) json.RawMessage {
	var out struct {
		Created json.RawMessage `json:"created"`
		Updated json.RawMessage `json:"updated"`
	}
	_ = json.Unmarshal(body, &out)
	switch {
	case out.Updated != nil:
		return out.Updated
	case out.Created != nil:
		return out.Created
	}
	return body
}

// InReview reports whether a write went to cvedexd's review queue instead of CVE Services.
func InReview(written json.RawMessage) bool {
	var out struct {
		State string `json:"state"`
	}
	return json.Unmarshal(written, &out) == nil && out.State == "in_review"
}
