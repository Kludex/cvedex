package github

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kludex/cvedex/cveservices"
)

// annotation is the title of the notices the reserve workflow leaves, one per ID it reserved.
const annotation = "cvedex"

// reserve runs the reserve workflow, which holds the CNA's key, and gives each ID it reserved a
// branch.
func reserve(g *repo, r *http.Request) any {
	query := r.URL.Query()
	var dispatched struct {
		ID int64 `json:"workflow_run_id"`
	}
	g.call(http.MethodPost, g.path("/actions/workflows/%s/dispatches", reserveWorkflow), map[string]any{
		"ref":                g.repository().DefaultBranch,
		"return_run_details": true,
		"inputs": map[string]string{
			"year":       query.Get("cve_year"),
			"count":      query.Get("amount"),
			"sequential": strconv.FormatBool(query.Get("batch_type") == "sequential"),
		},
	}, &dispatched)
	done := g.finish("reserve", func() run {
		var r run
		g.call(http.MethodGet, g.path("/actions/runs/%d", dispatched.ID), nil, &r)
		return r
	})
	var jobs struct {
		Jobs []struct {
			ID int64 `json:"id"`
		} `json:"jobs"`
	}
	g.call(http.MethodGet, g.path("/actions/runs/%d/jobs", dispatched.ID), nil, &jobs)
	ids := []cveservices.CVEID{}
	for _, job := range jobs.Jobs {
		var notices []struct {
			Title   string `json:"title"`
			Message string `json:"message"`
		}
		g.call(http.MethodGet, g.path("/check-runs/%d/annotations?per_page=100", job.ID), nil, &notices)
		for _, notice := range notices {
			if notice.Title != annotation || !cveID.MatchString(notice.Message) {
				continue
			}
			// 422 is a branch that is there already, from a run of the workflow outside cvedex.
			g.call(http.MethodPost, g.path("/git/refs"), map[string]string{
				"ref": "refs/heads/" + branchPrefix + notice.Message,
				"sha": done.SHA,
			}, nil, http.StatusUnprocessableEntity)
			ids = append(ids, cveservices.CVEID{
				ID:       notice.Message,
				Year:     notice.Message[4:8],
				State:    cveservices.StateReserved,
				Reserved: time.Now().UTC(),
				Cvedexd:  &cveservices.LocalState{State: "reserved"},
			})
		}
	}
	if len(ids) == 0 {
		g.fail(http.StatusBadGateway, "NO_IDS", "The reserve workflow reserved no ID: "+done.URL)
	}
	return map[string]any{"cve_ids": ids}
}

// list reads the CVE IDs off the repository: a record on the default branch is published, and a
// cve/ branch without one is reserved.
func list(g *repo, r *http.Request) any {
	query := r.URL.Query()
	for name := range query {
		if strings.HasPrefix(name, "time_") {
			g.fail(http.StatusBadRequest, "NOT_SUPPORTED", "A GitHub repository cannot filter CVE IDs by time")
		}
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
		} `json:"tree"`
	}
	// shortcut: GitHub cuts a tree off at 100,000 entries, read records/ alone when a repository gets there.
	g.call(http.MethodGet, g.path("/git/trees/%s?recursive=1", g.repository().DefaultBranch), nil, &tree)
	var refs []struct {
		Ref string `json:"ref"`
	}
	g.call(http.MethodGet, g.path("/git/matching-refs/heads/%s", branchPrefix), nil, &refs)

	found := map[string]*cveservices.CVEID{}
	add := func(id, state string, local *cveservices.LocalState) {
		if cveID.MatchString(id) && found[id] == nil {
			found[id] = &cveservices.CVEID{ID: id, Year: id[4:8], State: state, Cvedexd: local}
		}
	}
	for _, entry := range tree.Tree {
		id, isRecord := strings.CutPrefix(entry.Path, "records/")
		if isRecord {
			add(strings.TrimSuffix(id, ".json"), cveservices.StatePublished, nil)
		}
	}
	for _, ref := range refs {
		id := strings.TrimPrefix(ref.Ref, "refs/heads/"+branchPrefix)
		add(id, cveservices.StateReserved, &cveservices.LocalState{State: "reserved"})
	}
	// Newest first, so who and when end as those of the first pull request of each ID.
	for _, p := range g.pulls("state=all") {
		id := found[p.id()]
		if id == nil {
			continue
		}
		id.RequestedBy.User, id.Reserved = p.User.Login, p.CreatedAt
		if p.State == "open" {
			id.Cvedexd = &cveservices.LocalState{State: "in_review"}
			if note := g.changesRequested(p); note != "" {
				id.Cvedexd = &cveservices.LocalState{State: "reserved", Note: note}
			}
		}
	}

	ids := []cveservices.CVEID{}
	for _, key := range slices.Sorted(maps.Keys(found)) {
		id := found[key]
		if (query.Get("state") == "" || query.Get("state") == id.State) &&
			(query.Get("cve_id_year") == "" || query.Get("cve_id_year") == id.Year) {
			ids = append(ids, *id)
		}
	}
	return map[string]any{"cve_ids": ids}
}
