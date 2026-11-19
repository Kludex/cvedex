package github

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Kludex/cvedex/cveservices"
)

// review lists the open pull requests that hold a record nobody asked to change.
func review(g *repo, _ *http.Request) any {
	items := []cveservices.ReviewItem{}
	for _, p := range g.pulls("state=open") {
		cna, _, ok := g.file(p.id(), p.Head.SHA)
		if !ok || g.changesRequested(p) != "" {
			continue
		}
		item := cveservices.ReviewItem{
			CVEID:     p.id(),
			Submitter: p.User.Login,
			Action:    "publish",
			Revision:  g.pull(p.Number).Commits,
			Record:    container(cna),
			UpdatedAt: p.UpdatedAt,
		}
		if published, _, ok := g.file(p.id(), ""); ok {
			item.Published = container(published)
		}
		items = append(items, item)
	}
	return map[string]any{"cves": items}
}

func container(cna json.RawMessage) json.RawMessage {
	return json.RawMessage(`{"cnaContainer":` + string(cna) + `}`)
}

func (g *repo) pull(number int) pull {
	var p pull
	g.call(http.MethodGet, g.path("/pulls/%d", number), nil, &p)
	return p
}

// reviewed finds the pull request of the ID in the request, and fails unless it still is at the
// revision the reviewer read. It also returns the reviewer's note, if the request has one.
func (g *repo) reviewed(r *http.Request) (pull, string) {
	id := r.PathValue("id")
	var sent struct {
		Revision int    `json:"revision"`
		Note     string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&sent) // cvedex wrote it
	open, ok := g.open(id)
	if !ok {
		g.fail(http.StatusNotFound, "NOT_IN_REVIEW", id+" is not in review")
	}
	p := g.pull(open.Number)
	if p.Commits != sent.Revision {
		g.stale(id, sent.Revision)
	}
	return p, sent.Note
}

func (g *repo) stale(id string, revision int) {
	g.fail(http.StatusConflict, "STALE_REVISION", fmt.Sprintf("%s changed since revision %d", id, revision))
}

// approve merges the pull request, then waits for the publish workflow to send the record to CVE
// Services with the CNA's key.
func approve(g *repo, r *http.Request) any {
	id := r.PathValue("id")
	p, _ := g.reviewed(r)
	// GitHub refuses a review of your own pull request with a 422. Its branch rules, not cvedex,
	// decide whether the merge needs one.
	g.call(http.MethodPost, g.path("/pulls/%d/reviews", p.Number), map[string]string{
		"event":     "APPROVE",
		"commit_id": p.Head.SHA,
	}, nil, http.StatusUnprocessableEntity)
	var merged struct {
		SHA string `json:"sha"`
	}
	if !g.call(http.MethodPut, g.path("/pulls/%d/merge", p.Number), map[string]string{
		"sha":          p.Head.SHA,
		"merge_method": "squash",
	}, &merged, http.StatusConflict) {
		g.stale(id, p.Commits)
	}
	// 422 is a branch GitHub deleted itself on merge.
	g.call(http.MethodDelete, g.path("/git/refs/heads/%s", p.Head.Ref), nil, nil, http.StatusUnprocessableEntity)
	g.finish("publish", func() run {
		var runs struct {
			Runs []run `json:"workflow_runs"`
		}
		g.call(http.MethodGet, g.path("/actions/workflows/%s/runs?head_sha=%s", publishWorkflow, merged.SHA), nil, &runs)
		if len(runs.Runs) == 0 {
			return run{}
		}
		return runs.Runs[0]
	})
	return map[string]any{"created": wrapped(id, cveservices.StatePublished, nil)}
}

func requestChanges(g *repo, r *http.Request) any {
	p, note := g.reviewed(r)
	g.call(http.MethodPost, g.path("/pulls/%d/reviews", p.Number), map[string]string{
		"event":     "REQUEST_CHANGES",
		"body":      note,
		"commit_id": p.Head.SHA,
	}, nil)
	return map[string]string{"cve_id": r.PathValue("id"), "state": "reserved", "note": note}
}

// audit lists the repository's workflow runs, newest first: every write to CVE Services is one.
func audit(g *repo, r *http.Request) any {
	asked := r.URL.Query()
	page, _ := strconv.Atoi(cmp.Or(asked.Get("before"), "1"))
	query := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
	if actor := asked.Get("user"); actor != "" {
		query.Set("actor", actor)
	}
	if since := asked.Get("since"); since != "" {
		query.Set("created", ">="+since)
	}
	var runs struct {
		Runs []run `json:"workflow_runs"`
	}
	g.call(http.MethodGet, g.path("/actions/runs?%s", query.Encode()), nil, &runs)
	out := cveservices.AuditPage{Entries: []cveservices.AuditEntry{}}
	for _, run := range runs.Runs {
		entry := cveservices.AuditEntry{ID: run.Number, Time: run.CreatedAt, Actor: run.Actor.Login,
			ActorKind: run.Event, Method: run.Name, Path: run.Title}
		if run.Status == "completed" {
			status := http.StatusOK
			if run.Conclusion != "success" {
				status = http.StatusInternalServerError
			}
			entry.Status = &status
		}
		out.Entries = append(out.Entries, entry)
	}
	if len(runs.Runs) == 100 {
		page++
		out.Next = &page
	}
	return out
}
