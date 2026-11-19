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
	// Reserved is zero when the server does not know, as a GitHub repository may not.
	Reserved time.Time `json:"reserved,omitzero"`
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
	// Revision counts the records submitted for the ID.
	Revision int `json:"revision,omitempty"`
}

// ChangesRequested reports whether a reviewer sent the record back, with Note saying why.
func (s *LocalState) ChangesRequested() bool {
	return s != nil && s.State == "reserved" && s.Note != ""
}

// Label is the state as people read it.
func (s *LocalState) Label() string {
	if s.ChangesRequested() {
		return "changes requested"
	}
	return s.State
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

// IDFilter narrows ListIDs. Zero fields match everything.
type IDFilter struct {
	// State is StateReserved, StatePublished or StateRejected.
	State          string
	Year           int
	ReservedAfter  time.Time
	ReservedBefore time.Time
	ModifiedAfter  time.Time
	ModifiedBefore time.Time
}

// ListIDs returns every CVE ID of the org that matches filter. It follows pagination.
func (c *Client) ListIDs(ctx context.Context, filter IDFilter) ([]CVEID, error) {
	var ids []CVEID
	query := url.Values{}
	if filter.State != "" {
		query.Set("state", filter.State)
	}
	if filter.Year != 0 {
		query.Set("cve_id_year", strconv.Itoa(filter.Year))
	}
	for name, at := range map[string]time.Time{
		"time_reserved.gt": filter.ReservedAfter,
		"time_reserved.lt": filter.ReservedBefore,
		"time_modified.gt": filter.ModifiedAfter,
		"time_modified.lt": filter.ModifiedBefore,
	} {
		if !at.IsZero() {
			query.Set(name, at.UTC().Format(time.RFC3339))
		}
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

// ID returns one CVE ID of the org.
func (c *Client) ID(ctx context.Context, id string) (*CVEID, error) {
	var out CVEID
	err := c.Do(ctx, http.MethodGet, "/api/cve-id/"+url.PathEscape(id), nil, nil, &out)
	return &out, err
}

// SetIDState rejects a reserved ID that has no record, with StateRejected, or reserves it again,
// with StateReserved.
func (c *Client) SetIDState(ctx context.Context, id, state string) error {
	query := url.Values{"state": {state}}
	return c.Do(ctx, http.MethodPut, "/api/cve-id/"+url.PathEscape(id), query, nil, nil)
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

// Reject publishes a rejected record for a CVE ID and returns it. cna holds `rejectedReasons`
// and optionally `replacedBy`. A published record is replaced, so Reject asks for the ID's state
// first.
func (c *Client) Reject(ctx context.Context, id string, cna json.RawMessage) (json.RawMessage, error) {
	current, err := c.ID(ctx, id)
	if err != nil {
		return nil, err
	}
	method := http.MethodPost
	if current.State == StatePublished {
		method = http.MethodPut
	}
	return c.writeRecord(ctx, method, "/api/cve/"+url.PathEscape(id)+"/reject", cna)
}

// ADP adds or replaces the client's ADP container on a published record and returns the record.
// Only users of an org with the ADP role can.
func (c *Client) ADP(ctx context.Context, id string, adp json.RawMessage) (json.RawMessage, error) {
	var body json.RawMessage
	path := "/api/cve/" + url.PathEscape(id) + "/adp"
	err := c.Do(ctx, http.MethodPut, path, nil, map[string]json.RawMessage{"adpContainer": adp}, &body)
	return written(body), err
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
