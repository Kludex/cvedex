// Package github serves the cvedexd API from a GitHub repository, so cvedex works against one with
// no server to run. A reserved CVE ID is a branch, a record in review is a pull request, and
// approving merges it. The repository's workflows hold the CNA's key: one reserves IDs, the other
// publishes what is merged. GitHub's permissions and branch rules decide who may do what.
package github

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Kludex/cvedex/cveservices"
)

var (
	repoURL = regexp.MustCompile(`^(?i:https://(?:www\.)?github\.com)/([\w.-]+)/([\w.-]+?)/?$`)
	cveID   = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// Repo splits the URL of a GitHub repository, such as https://github.com/acme/cves, into its
// owner and name. ok is false for any other URL.
func Repo(url string) (owner, name string, ok bool) {
	parts := repoURL.FindStringSubmatch(url)
	if parts == nil {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// IsRepo reports whether url is a GitHub repository.
func IsRepo(url string) bool {
	return repoURL.MatchString(url)
}

// API is where GitHub's API is: GITHUB_API_URL, else https://api.github.com.
func API() string {
	return strings.TrimSuffix(cmp.Or(os.Getenv("GITHUB_API_URL"), "https://api.github.com"), "/")
}

// Token returns the GitHub token to use: GH_TOKEN or GITHUB_TOKEN, else the GitHub CLI's login for
// the API's host, or "" when gh is missing or logged out. The host drops "api.", so api.github.com
// is github.com.
func Token(ctx context.Context) string {
	if token := cmp.Or(os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN")); token != "" {
		return token
	}
	u, err := neturl.Parse(API())
	if err != nil {
		return ""
	}
	out, err := exec.CommandContext(ctx, "gh", "auth", "token", "--hostname", strings.TrimPrefix(u.Host, "api.")).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Client returns an HTTP client that answers the cvedexd API from the repository in the request's
// URL, as the GitHub user token belongs to. Nothing is sent to that URL itself.
func Client(token string) *http.Client {
	mux := http.NewServeMux()
	route := func(pattern string, serve func(*repo, *http.Request) any) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			g := &repo{ctx: r.Context(), token: token, owner: r.PathValue("owner"), name: r.PathValue("repo")}
			var out any
			if id := r.PathValue("id"); id != "" && !cveID.MatchString(id) {
				g.fail(http.StatusBadRequest, "BAD_INPUT", fmt.Sprintf("%q is not a CVE ID", id))
			} else {
				out = serve(g, r)
			}
			if g.failed != nil {
				w.WriteHeader(g.failed.Status)
				out = g.failed
			}
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	const api = " /{owner}/{repo}/api"
	route("GET"+api+"/health-check", func(*repo, *http.Request) any {
		return cveservices.Health{Server: "cvedexd", Version: "on GitHub"}
	})
	route("GET"+api+"/org/{org}/user/{user...}", user)
	route("POST"+api+"/cve-id", reserve)
	route("GET"+api+"/cve-id", list)
	route("GET"+api+"/cve/{id}", record)
	route("POST"+api+"/cve/{id}/cna", submit)
	route("PUT"+api+"/cve/{id}/cna", submit)
	route("GET"+api+"/cvedexd/review", review)
	route("POST"+api+"/cvedexd/cve/{id}/approve", approve)
	route("POST"+api+"/cvedexd/cve/{id}/request-changes", requestChanges)
	route("GET"+api+"/cvedexd/audit", audit)
	route("GET"+api+"/cvedexd/proposals", func(g *repo, _ *http.Request) any {
		g.fail(http.StatusForbidden, "NOT_ALLOWED", "A GitHub repository has no proposals: an agent's pull request "+
			"waits in cvedex review")
		return nil
	})
	route("/", func(g *repo, _ *http.Request) any {
		g.fail(http.StatusNotFound, "NOT_SUPPORTED", "A GitHub repository does not do this: it reserves IDs, and "+
			"takes records for review")
		return nil
	})
	return &http.Client{Transport: transport{mux}}
}

type transport struct{ handler http.Handler }

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// failure is an error, answered the way CVE Services answers one.
type failure struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message"`
}

func user(g *repo, _ *http.Request) any {
	var me struct {
		Login string `json:"login"`
	}
	g.call(http.MethodGet, "/user", nil, &me)
	may, role := g.repository().Permissions, "read"
	if may.Push {
		role = "write"
	}
	if may.Admin {
		role = "admin"
	}
	roles := cveservices.Authority{ActiveRoles: []string{role}}
	return cveservices.User{Username: me.Login, Active: true, Authority: roles}
}
