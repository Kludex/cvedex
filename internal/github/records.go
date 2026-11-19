package github

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Kludex/cvedex/cveservices"
)

// record shows the record of an ID as the repository holds it: the one in review when a pull
// request is open, else the one on the default branch.
func record(g *repo, r *http.Request) any {
	id := r.PathValue("id")
	state, ref := cveservices.StatePublished, ""
	if p, ok := g.open(id); ok {
		state, ref = "IN_REVIEW", p.Head.SHA
	}
	cna, _, ok := g.file(id, ref)
	if !ok {
		g.fail(http.StatusNotFound, "CVE_RECORD_DNE", "The cve record for the cve id does not exist.")
	}
	return wrapped(id, state, cna)
}

func wrapped(id, state string, cna json.RawMessage) any {
	return map[string]any{
		"dataType":    "CVE_RECORD",
		"cveMetadata": map[string]string{"cveId": id, "state": state},
		"containers":  map[string]json.RawMessage{"cna": cna},
	}
}

// submit commits a record to its ID's branch and opens a pull request for it, unless one is open.
func submit(g *repo, r *http.Request) any {
	id := r.PathValue("id")
	var sent struct {
		CNA json.RawMessage `json:"cnaContainer"`
	}
	_ = json.NewDecoder(r.Body).Decode(&sent) // cvedex wrote it
	var cna struct {
		Title string `json:"title"`
	}
	_ = json.Unmarshal(sent.CNA, &cna)
	title := id
	if cna.Title != "" {
		title += ": " + cna.Title
	}
	var content bytes.Buffer
	_ = json.Indent(&content, sent.CNA, "", "  ")
	content.WriteByte('\n')

	base, branch := g.repository().DefaultBranch, branchPrefix+id
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if !g.call(http.MethodGet, g.path("/git/ref/heads/%s", branch), nil, &ref, http.StatusNotFound) {
		g.call(http.MethodGet, g.path("/git/ref/heads/%s", base), nil, &ref)
		g.call(http.MethodPost, g.path("/git/refs"), map[string]string{
			"ref": "refs/heads/" + branch,
			"sha": ref.Object.SHA,
		}, nil)
	}
	commit := map[string]string{
		"message": title,
		"branch":  branch,
		"content": base64.StdEncoding.EncodeToString(content.Bytes()),
	}
	if _, sha, ok := g.file(id, branch); ok {
		commit["sha"] = sha
	}
	g.call(http.MethodPut, g.path("/contents/%s", recordPath(id)), commit, nil)
	p, ok := g.open(id)
	if !ok {
		g.call(http.MethodPost, g.path("/pulls"), map[string]string{
			"title": title,
			"head":  branch,
			"base":  base,
			"body":  "Sent with `cvedex`. Read it with `cvedex review show " + id + "`.",
		}, &p)
	}
	return map[string]string{"message": id + " is in review", "state": "in_review", "url": p.URL}
}
