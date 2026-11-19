package github

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	branchPrefix    = "cve/"
	reserveWorkflow = "cvedex-reserve.yml"
	publishWorkflow = "cvedex-publish.yml"
	// maxBody caps what is read of one answer from GitHub.
	maxBody = 16 << 20
	// attempts bounds the wait for a workflow run, to five minutes at the default Interval.
	attempts = 150
)

// Interval is how long to wait between two looks at a workflow run.
var Interval = 2 * time.Second

var client = &http.Client{Timeout: time.Minute}

// repo is one request's view of a repository.
type repo struct {
	ctx                context.Context
	token, owner, name string
	// failed is the first failure. Calls after it do nothing, so a handler reads straight through
	// and the failure is answered once.
	failed *failure
}

func (g *repo) fail(status int, code, message string) {
	if g.failed == nil {
		g.failed = &failure{status, code, message}
	}
}

// unreachable fails for an error that is not an answer from GitHub.
func (g *repo) unreachable(err error) bool {
	g.fail(http.StatusBadGateway, "GITHUB_UNREACHABLE", err.Error())
	return false
}

// path is a path of GitHub's API inside the repository.
func (g *repo) path(format string, args ...any) string {
	return "/repos/" + g.owner + "/" + g.name + fmt.Sprintf(format, args...)
}

// call sends one request to GitHub's API and decodes its JSON answer into out, which may be nil. A
// *string takes the answer as text. It reports whether GitHub did it. A status in allowed is no
// failure: the caller handles it.
func (g *repo) call(method, path string, body, out any, allowed ...int) bool {
	if g.failed != nil {
		return false
	}
	var payload io.Reader
	if body != nil {
		data, _ := json.Marshal(body) // maps of strings and booleans always marshal
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(g.ctx, method, API()+path, payload)
	if err != nil {
		return g.unreachable(err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("User-Agent", "cvedex")
	res, err := client.Do(req)
	if err != nil {
		return g.unreachable(err)
	}
	defer func() { _ = res.Body.Close() }()
	answer := io.LimitReader(res.Body, maxBody)
	text, isText := out.(*string)
	switch {
	case slices.Contains(allowed, res.StatusCode):
		return false
	case res.StatusCode >= http.StatusMultipleChoices:
		var problem struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(answer).Decode(&problem)
		// Only these are the caller's own. cvedex would also answer a 429 by sending everything again.
		status := res.StatusCode
		if !slices.Contains([]int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}, status) {
			status = http.StatusBadGateway
		}
		g.fail(status, "GITHUB_ERROR", fmt.Sprintf("GitHub: %s (%s %s)", cmp.Or(problem.Message, res.Status), method, path))
	case isText:
		data, _ := io.ReadAll(answer) // a log cut short still has the lines before the cut
		*text = string(data)
	case out != nil:
		if err := json.NewDecoder(answer).Decode(out); err != nil {
			return g.unreachable(fmt.Errorf("reading GitHub's answer to %s %s: %w", method, path, err))
		}
	}
	return g.failed == nil
}

type repository struct {
	DefaultBranch string `json:"default_branch"`
	Permissions   struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
	} `json:"permissions"`
}

func (g *repo) repository() repository {
	var r repository
	g.call(http.MethodGet, g.path(""), nil, &r)
	return r
}

type pull struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	URL    string `json:"html_url"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
	// Commits is only set on a pull request read alone.
	Commits int `json:"commits"`
}

func (p pull) id() string {
	return strings.TrimPrefix(p.Head.Ref, branchPrefix)
}

// pulls lists the pull requests of CVE branches, newest first.
// shortcut: only the 100 newest pull requests, paginate when a repository outgrows it.
func (g *repo) pulls(query string) []pull {
	var all []pull
	g.call(http.MethodGet, g.path("/pulls?per_page=100&%s", query), nil, &all)
	return slices.DeleteFunc(all, func(p pull) bool { return !cveID.MatchString(p.id()) })
}

// open is the open pull request of id's branch, if there is one.
func (g *repo) open(id string) (pull, bool) {
	open := g.pulls("state=open&head=" + g.owner + ":" + branchPrefix + id)
	if len(open) == 0 {
		return pull{}, false
	}
	return open[0], true
}

// changesRequested is the note of the last reviewer who asked for changes to the pull request as
// it is now, or "".
func (g *repo) changesRequested(p pull) string {
	var reviews []struct {
		State string `json:"state"`
		Body  string `json:"body"`
		SHA   string `json:"commit_id"`
	}
	g.call(http.MethodGet, g.path("/pulls/%d/reviews?per_page=100", p.Number), nil, &reviews)
	note := ""
	for _, review := range reviews {
		if review.State == "CHANGES_REQUESTED" && review.SHA == p.Head.SHA {
			note = review.Body
		}
	}
	return note
}

func recordPath(id string) string {
	return "records/" + id + ".json"
}

// file reads id's record at ref, or on the default branch for "". It returns the CNA container
// and the blob's SHA, which GitHub wants to replace the file.
func (g *repo) file(id, ref string) (cna json.RawMessage, sha string, ok bool) {
	var content struct {
		Content string `json:"content"`
		SHA     string `json:"sha"`
	}
	path := g.path("/contents/%s", recordPath(id))
	if ref != "" {
		path += "?ref=" + ref
	}
	if !g.call(http.MethodGet, path, nil, &content, http.StatusNotFound) {
		return nil, "", false
	}
	data, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	if !json.Valid(data) {
		g.fail(http.StatusBadGateway, "BAD_RECORD", recordPath(id)+" in the repository is not JSON")
	}
	return data, content.SHA, g.failed == nil
}

type run struct {
	ID         int64  `json:"id"`
	Number     int    `json:"run_number"`
	Name       string `json:"name"`
	Title      string `json:"display_title"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	SHA        string `json:"head_sha"`
	URL        string `json:"html_url"`
	CreatedAt  string `json:"created_at"`
	Actor      struct {
		Login string `json:"login"`
	} `json:"actor"`
}

// finish waits for the workflow run that find looks up to end, and fails unless it succeeded.
func (g *repo) finish(workflow string, find func() run) run {
	for range attempts {
		r := find()
		if g.failed != nil || r.Status == "completed" {
			if r.Conclusion != "success" {
				g.fail(http.StatusBadGateway, "WORKFLOW_FAILED", "The "+workflow+" workflow failed: "+r.URL)
			}
			return r
		}
		time.Sleep(Interval)
	}
	g.fail(http.StatusGatewayTimeout, "WORKFLOW_RUNNING", "The "+workflow+" workflow has not finished yet. "+
		"See "+g.htmlURL()+"/actions")
	return run{}
}

func (g *repo) htmlURL() string {
	return "https://github.com/" + g.owner + "/" + g.name
}
