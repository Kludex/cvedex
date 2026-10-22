package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/cassette"
	"github.com/Kludex/cvedex/internal/cli"
)

type result struct {
	stdout, stderr string
	code           int
}

// run runs cvedex logged in as alice@acme.test of the acme CNA, against url.
func run(t *testing.T, url, stdin string, args ...string) result {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", url)
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "key")
	var stdout, stderr bytes.Buffer
	code := cli.Main(context.Background(), args, strings.NewReader(stdin), &stdout, &stderr)
	return result{stdout.String(), stderr.String(), code}
}

func cvedexd(exchanges ...cassette.Exchange) []cassette.Exchange {
	health := cassette.Exchange{
		Method:   "GET",
		Path:     "/api/health-check",
		Response: `{"server":"cvedexd","version":"0.1.0"}`,
	}
	return append([]cassette.Exchange{health}, exchanges...)
}

func TestCommands(t *testing.T) {
	publish := cassette.Load(t, "publish")
	var sent struct {
		CNA json.RawMessage `json:"cnaContainer"`
	}
	if err := json.Unmarshal([]byte(publish.Body), &sent); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bare := filepath.Join(dir, "bare.json")
	wrapped := filepath.Join(dir, "wrapped.json")
	full := filepath.Join(dir, "full.json")
	broken := filepath.Join(dir, "broken.json")
	for path, data := range map[string]string{
		bare:    string(sent.CNA),
		wrapped: publish.Body,
		full:    `{"dataType":"CVE_RECORD","containers":{"cna":` + string(sent.CNA) + `}}`,
		broken:  "not json",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	review := `{"cves":[{"cve_id":"CVE-2026-1100","submitter":"bob","updated_at":"2026-10-22T10:00:00Z",` +
		`"record":{"cnaContainer":{"title":"Path traversal in widget"}}}]}`

	tests := []struct {
		name      string
		exchanges []cassette.Exchange
		stdin     string
		args      []string
		code      int
		stdout    []string
		stderr    []string
	}{
		{
			name: "status",
			exchanges: []cassette.Exchange{
				cassette.Load(t, "health-check"),
				cassette.Load(t, "user"),
				cassette.Load(t, "org"),
			},
			args:   []string{"status"},
			stdout: []string{"CVE Services", "alice@acme.test", "ADMIN", "(acme)"},
		},
		{
			name: "status as JSON",
			exchanges: []cassette.Exchange{
				cassette.Load(t, "health-check"),
				cassette.Load(t, "user"),
				cassette.Load(t, "org"),
			},
			args:   []string{"status", "--json"},
			stdout: []string{`"server": "CVE Services"`, `"username": "alice@acme.test"`, `"short_name": "acme"`},
		},
		{
			name: "status as a cvedexd submitter",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: cassette.Load(t, "user").Path, Status: 403,
				Response: `{"error":"NOT_ALLOWED","message":"Submitters can only reserve IDs and submit records"}`}),
			args:   []string{"status"},
			stdout: []string{"cvedexd 0.1.0", "alice@acme.test  submitter"},
		},
		{
			name: "list with a reviewer's note",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve-id",
				Response: `{"cve_ids":[{"cve_id":"CVE-2026-1102","state":"RESERVED",` +
					`"cvedexd":{"state":"reserved","note":"Add a CWE."}},` +
					`{"cve_id":"CVE-2026-1103","state":"RESERVED","cvedexd":{"state":"in_review"}}]}`}},
			args: []string{"list"},
			stdout: []string{"RESERVED (changes requested)", "RESERVED (in_review)", "Changes requested",
				"CVE-2026-1102: Add a CWE."},
		},
		{
			name:      "list",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-id-list")},
			args:      []string{"ls"},
			stdout:    []string{"CVE ID", "CVE-2026-1100", "PUBLISHED", "alice@acme.test"},
		},
		{
			name: "list empty",
			exchanges: []cassette.Exchange{
				{Method: "GET", Path: "/api/cve-id?state=RESERVED", Response: `{"cve_ids":[]}`},
			},
			args:   []string{"list", "--state", "reserved"},
			stdout: []string{"No CVE IDs. Reserve one with cvedex reserve."},
		},
		{
			name:   "list in an unknown state",
			args:   []string{"list", "--state", "lost"},
			code:   1,
			stderr: []string{`--state must be reserved, published or rejected, not "LOST"`},
		},
		{
			name:      "show without the CVE prefix",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-2025-0001")},
			args:      []string{"show", "2025-0001"},
			stdout:    []string{"CVE-2025-0001", "PUBLISHED", "References"},
		},
		{
			name:      "show as JSON",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-2025-0001")},
			args:      []string{"show", "cve-2025-0001", "--json"},
			stdout:    []string{`"cveId": "CVE-2025-0001"`},
		},
		{
			name:      "show a record that does not exist",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-record-dne")},
			args:      []string{"show", "CVE-2021-44228"},
			code:      1,
			stderr:    []string{"Error: The cve record for the cve id does not exist. (CVE_RECORD_DNE)"},
		},
		{
			name:      "show a record that does not exist as JSON",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-record-dne")},
			args:      []string{"show", "CVE-2021-44228", "--json"},
			code:      1,
			stderr:    []string{`"error":"CVE_RECORD_DNE"`},
		},
		{
			name:      "reserve",
			exchanges: []cassette.Exchange{cassette.Load(t, "reserve")},
			args:      []string{"reserve", "--year", "2026"},
			stdout:    []string{"Reserved 1 CVE ID", "CVE-2026-1100", "cvedex publish CVE-2026-1100 record.json"},
		},
		{
			name: "reserve through an agent token",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
				Status: 202, Response: `{"proposal_id":"p1"}`}},
			args:   []string{"reserve", "--year", "2026"},
			code:   1,
			stderr: []string{"Waiting for approval as proposal p1", "cvedex proposals approve p1"},
		},
		{
			name: "reserve several",
			exchanges: []cassette.Exchange{
				{Method: "POST", Path: "/api/cve-id?amount=2&batch_type=sequential&cve_year=2026&short_name=acme",
					Response: `{"cve_ids":[{"cve_id":"CVE-2026-1"},{"cve_id":"CVE-2026-2"}]}`},
			},
			args:   []string{"reserve", "--year", "2026", "-n", "2", "--sequential"},
			stdout: []string{"Reserved 2 CVE IDs", "CVE-2026-1", "CVE-2026-2"},
		},
		{
			name:      "publish a bare container",
			exchanges: []cassette.Exchange{publish},
			args:      []string{"publish", "CVE-2026-1100", bare},
			stdout:    []string{"Published CVE-2026-1100", "Affected"},
		},
		{
			name:      "publish a wrapped container",
			exchanges: []cassette.Exchange{publish},
			args:      []string{"publish", "CVE-2026-1100", wrapped},
			stdout:    []string{"Published CVE-2026-1100"},
		},
		{
			name:      "publish a full record",
			exchanges: []cassette.Exchange{publish},
			args:      []string{"publish", "CVE-2026-1100", full},
			stdout:    []string{"Published CVE-2026-1100"},
		},
		{name: "publish from stdin", exchanges: []cassette.Exchange{publish}, stdin: string(sent.CNA),
			args: []string{"publish", "CVE-2026-1100", "-"}, stdout: []string{"Published CVE-2026-1100"}},
		{
			name: "publish as a cvedexd submitter",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/cve/CVE-2026-1100/cna", Body: publish.Body,
				Response: `{"message":"CVE-2026-1100 was submitted for review","state":"in_review"}`}},
			args:   []string{"publish", "CVE-2026-1100", bare},
			stdout: []string{"Sent CVE-2026-1100 for review"},
		},
		{
			name:      "publish an invalid record",
			exchanges: []cassette.Exchange{cassette.Load(t, "bad-request")},
			args:      []string{"publish", "CVE-2026-1100", "-"},
			stdin:     `{}`,
			code:      1,
			stderr:    []string{"Error:", "INVALID_JSON_SCHEMA", "/cnaContainer"},
		},
		{name: "publish a file that is not JSON", args: []string{"publish", "CVE-2026-1100", broken}, code: 1,
			stderr: []string{"broken.json is not a JSON object"}},
		{
			name:   "publish a missing file",
			args:   []string{"publish", "CVE-2026-1100", filepath.Join(dir, "missing.json")},
			code:   1,
			stderr: []string{"no such file"},
		},
		{
			name:   "publish on production without a terminal",
			args:   []string{"publish", "CVE-2026-1100", bare, "--url", "https://cveawg.mitre.org"},
			code:   1,
			stderr: []string{"publish needs --yes when there is no terminal to ask"},
		},
		{
			name: "update",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/cve/CVE-2026-1100/cna", Body: publish.Body,
				Response: `{"updated":{"cveMetadata":{"cveId":"CVE-2026-1100","state":"PUBLISHED"}}}`}},
			args:   []string{"update", "CVE-2026-1100", bare},
			stdout: []string{"Updated CVE-2026-1100"},
		},
		{
			name: "reject",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/cve/CVE-2026-1100/reject",
				Body:     `{"cnaContainer":{"rejectedReasons":[{"lang":"en","value":"Duplicate."}]}}`,
				Response: `{"created":{"cveMetadata":{"cveId":"CVE-2026-1100","state":"REJECTED"}}}`}},
			args:   []string{"reject", "CVE-2026-1100", "--reason", "Duplicate."},
			stdout: []string{"Rejected CVE-2026-1100", "REJECTED"},
		},
		{
			name:   "reject without a reason",
			args:   []string{"reject", "CVE-2026-1100"},
			code:   1,
			stderr: []string{"--reason is required"},
		},
		{
			name:      "org",
			exchanges: []cassette.Exchange{cassette.Load(t, "org")},
			args:      []string{"org"},
			stdout:    []string{"acme", "Roles", "ID quota"},
		},
		{
			name: "org users",
			exchanges: []cassette.Exchange{
				{Method: "GET", Path: "/api/org/acme/users", Response: `{"nextPage":2,"users":[` +
					`{"username":"alice@acme.test","name":{"first":"Alice","last":"Smith"},"active":true,` +
					`"authority":{"active_roles":["ADMIN"]}}]}`},
				{Method: "GET", Path: "/api/org/acme/users?page=2", Response: `{"users":[` +
					`{"username":"bob@acme.test","name":{"first":"Bob"},"active":false,"authority":{"active_roles":[]}}]}`},
			},
			args:   []string{"org", "users"},
			stdout: []string{"alice@acme.test", "Alice Smith", "ADMIN", "active", "bob@acme.test", "inactive"},
		},
		{
			name: "status without roles",
			exchanges: []cassette.Exchange{
				cassette.Load(t, "health-check"),
				{Method: "GET", Path: cassette.Load(t, "user").Path, Response: `{"username":"alice@acme.test"}`},
				cassette.Load(t, "org"),
			},
			args:   []string{"status"},
			stdout: []string{"alice@acme.test\n"},
		},
		{
			name: "status when the org lookup fails",
			exchanges: []cassette.Exchange{
				cassette.Load(t, "health-check"),
				cassette.Load(t, "user"),
				{Method: "GET", Path: cassette.Load(t, "org").Path, Status: 500, Response: `{"message":"Org lookup failed"}`},
			},
			args:   []string{"status"},
			code:   1,
			stderr: []string{"Org lookup failed"},
		},
		{
			name: "show a record's severity, ranges and non-English description",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve/CVE-2026-1200", Response: `{` +
				`"cveMetadata":{"cveId":"CVE-2026-1200","state":"PUBLISHED"},"containers":{"cna":{` +
				`"descriptions":[{"lang":"es","value":"Desbordamiento."},{"lang":"en"}],` +
				`"metrics":[{"cvssV3_1":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}],` +
				`"affected":[{"vendor":"acme","product":"widget","versions":[` +
				`{"version":"1.0","lessThanOrEqual":"1.4","status":"affected"},{"version":"2.0","status":"unaffected"}]}]}}}`}},
			args:   []string{"show", "2026-1200"},
			stdout: []string{"7.5 HIGH  CVSS:3.1/AV:N", "Desbordamiento.", "acme widget  1.0 to 1.4, 2.0 (unaffected)"},
		},
		{
			name: "show a rejected record",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve/CVE-2026-1201", Response: `{` +
				`"cveMetadata":{"cveId":"CVE-2026-1201","state":"REJECTED","dateRejected":"2026-10-01T00:00:00Z"},` +
				`"containers":{"cna":{"rejectedReasons":[{"lang":"en","value":"Duplicate of CVE-2026-1200."}],` +
				`"metrics":[{"cvssV4_0":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"CVSS:4.0/AV:N"}}]}}}`}},
			args:   []string{"show", "2026-1201"},
			stdout: []string{"REJECTED", "Rejected", "2026-10-01", "5.0 MEDIUM", "Duplicate of CVE-2026-1200."},
		},
		{
			name: "org add-user without roles",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/org/acme/user",
				Body:     `{"authority":{"active_roles":[]},"name":{"first":"Bob","last":"Smith"},"username":"bob@acme.test"}`,
				Response: `{"created":{"username":"bob@acme.test"}}`}},
			args:   []string{"org", "add-user", "bob@acme.test", "--first", "Bob", "--last", "Smith"},
			stdout: []string{"bob@acme.test"},
		},
		{
			name: "proposals deny as text",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/proposals/p1/deny",
				Response: `{"id":"p1","status":"denied"}`}),
			args:   []string{"proposals", "deny", "p1"},
			stdout: []string{"Denied proposal p1."},
		},
		{
			name: "org add-user",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/org/acme/user",
				Body: `{"authority":{"active_roles":["ADMIN"]},"name":{"first":"Bob","last":"Smith"},` +
					`"username":"bob@acme.test"}`,
				Response: `{"created":{"username":"bob@acme.test"}}`}},
			args:   []string{"org", "add-user", "bob@acme.test", "--first", "Bob", "--last", "Smith", "--admin"},
			stdout: []string{"Added bob@acme.test", "cvedex org reset-key bob@acme.test"},
		},
		{
			name: "org reset-key",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/org/acme/user/bob@acme.test/reset_secret",
				Response: `{"API-secret":"new-key"}`}},
			args:   []string{"org", "reset-key", "bob@acme.test", "--yes"},
			stdout: []string{"New API key for bob@acme.test", "new-key", "shown once"},
		},
		{name: "org reset-key without a terminal", args: []string{"org", "reset-key", "bob@acme.test"}, code: 1,
			stderr: []string{"reset-key needs --yes"}},
		{
			name:      "review on CVE Services",
			exchanges: []cassette.Exchange{cassette.Load(t, "health-check")},
			args:      []string{"review"},
			code:      1,
			stderr:    []string{"cvedex review needs a cvedexd server"},
		},
		{
			name:      "review",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: review}),
			args:      []string{"review"},
			stdout:    []string{"CVE-2026-1100", "bob", "2026-10-22", "Path traversal in widget"},
		},
		{
			name:      "review empty",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: `{"cves":[]}`}),
			args:      []string{"review"},
			stdout:    []string{"Nothing to review."},
		},
		{
			name:      "review show",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: review}),
			args:      []string{"review", "show", "2026-1100"},
			stdout:    []string{"CVE-2026-1100", "from bob", "Path traversal in widget"},
		},
		{
			name:      "review show an ID not in review",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: review}),
			args:      []string{"review", "show", "CVE-2026-1"},
			code:      1,
			stderr:    []string{"CVE-2026-1 is not in review"},
		},
		{
			name: "review approve",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/approve",
				Response: `{"created":{"cveMetadata":{"cveId":"CVE-2026-1100","state":"PUBLISHED"}}}`}),
			args:   []string{"review", "approve", "CVE-2026-1100"},
			stdout: []string{"Published CVE-2026-1100"},
		},
		{
			name: "review request-changes",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/request-changes",
				Body: `{"note":"Add the CWE."}`, Response: `{"cve_id":"CVE-2026-1100","state":"reserved","note":"Add the CWE."}`}),
			args:   []string{"review", "request-changes", "CVE-2026-1100", "Add the CWE."},
			stdout: []string{"Sent CVE-2026-1100 back to its submitter."},
		},
		{
			name: "proposals",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
					`{"id":"p1","method":"POST","path":"/api/cve-id?amount=1","body":null,"created_at":"2026-10-22T10:00:00Z"}]}`},
			),
			args:   []string{"proposals"},
			stdout: []string{"p1", "POST /api/cve-id?amount=1", "2026-10-22"},
		},
		{
			name: "proposals empty",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
			),
			args:   []string{"proposals"},
			stdout: []string{"No pending proposals."},
		},
		{
			name: "proposals approve",
			exchanges: cvedexd(
				cassette.Exchange{
					Method:   "POST",
					Path:     "/api/cvedexd/proposals/p1/approve",
					Response: `{"cve_ids":[]}`,
				},
			),
			args:   []string{"proposals", "approve", "p1"},
			stdout: []string{"Approved proposal p1"},
		},
		{
			name: "proposals deny",
			exchanges: cvedexd(
				cassette.Exchange{
					Method:   "POST",
					Path:     "/api/cvedexd/proposals/p1/deny",
					Response: `{"id":"p1","status":"denied"}`,
				},
			),
			args:   []string{"proposals", "deny", "p1", "--json"},
			stdout: []string{`"status": "denied"`},
		},
		{
			name: "audit",
			exchanges: cvedexd(
				cassette.Exchange{
					Method: "GET",
					Path:   "/api/cvedexd/audit?since=2026-01-01&user=bob",
					Response: `{"audit":[` +
						`{"id":1,"ts":"2026-10-22T10:00:00.000Z","actor":"bob","actor_kind":"agent",` +
						`"method":"POST","path":"/api/cve-id","status":202},` +
						`{"id":2,"ts":"2026-10-22T10:01:00.000Z","actor":null,"actor_kind":null,` +
						`"method":"GET","path":"/api/cve-id","status":401}]}`,
				},
			),
			args:   []string{"audit", "--user", "bob", "--since", "2026-01-01"},
			stdout: []string{"2026-10-22 10:00:00", "bob", "agent", "POST /api/cve-id", "202", "401"},
		},
		{
			name: "submitter add",
			exchanges: cvedexd(
				cassette.Exchange{Method: "POST", Path: "/api/cvedexd/submitters", Body: `{"name":"bob"}`, Status: 201,
					Response: `{"id":7,"name":"bob","kind":"user","token":"cvx_secret"}`},
			),
			args:   []string{"submitter", "add", "bob"},
			stdout: []string{"Created submitter bob (ID 7)", "New user token", "cvx_secret"},
		},
		{
			name: "submitter token",
			exchanges: cvedexd(
				cassette.Exchange{
					Method:   "POST",
					Path:     "/api/cvedexd/submitters/7/tokens",
					Body:     `{"kind":"agent"}`,
					Status:   201,
					Response: `{"kind":"agent","token":"cvx_agent"}`,
				},
			),
			args:   []string{"submitter", "token", "7", "--agent"},
			stdout: []string{"New agent token", "cvx_agent"},
		},
		{
			name:      "submitter token for a bad ID",
			exchanges: cvedexd(),
			args:      []string{"submitter", "token", "bob"},
			code:      1,
			stderr:    []string{`submitter ID must be a number, not "bob"`},
		},
		{
			name: "list several pages",
			exchanges: []cassette.Exchange{
				{Method: "GET", Path: "/api/cve-id", Response: `{"nextPage":2,"cve_ids":[{"cve_id":"CVE-2026-1"}]}`},
				{Method: "GET", Path: "/api/cve-id?page=2", Response: `{"cve_ids":[{"cve_id":"CVE-2026-2"}]}`},
			},
			args:   []string{"list"},
			stdout: []string{"CVE-2026-1", "CVE-2026-2"},
		},
		{
			name: "forbidden",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/org/acme/users", Status: 403,
				Response: `{"error":"NOT_ORG_ADMIN","message":"Only org admins can.","details":"admins only"}`}},
			args: []string{"org", "users"},
			code: 1,
			stderr: []string{
				"Only org admins can. (NOT_ORG_ADMIN)",
				"admins only",
				"Your user is not allowed to do this.",
			},
		},
		{
			name: "invalid parameters",
			exchanges: []cassette.Exchange{
				{Method: "POST", Path: "/api/cve-id?amount=1&cve_year=1990&short_name=acme", Status: 400,
					Response: `{"error":"BAD_INPUT","message":"Parameters were invalid",` +
						`"details":[{"param":"cve_year","msg":"must be 1999 or later"}]}`},
			},
			args:   []string{"reserve", "--year", "1990"},
			code:   1,
			stderr: []string{"Parameters were invalid (BAD_INPUT)", "cve_year: must be 1999 or later"},
		},
		{
			name:   "invalid URL",
			args:   []string{"list", "--url", "nowhere"},
			code:   1,
			stderr: []string{`invalid URL "nowhere"`},
		},
		{
			name:   "completion without credentials",
			args:   []string{"completion", "bash"},
			stdout: []string{"complete -o default"},
		},
		{
			name:   "unknown command",
			args:   []string{"frobnicate"},
			code:   1,
			stderr: []string{`unknown command "frobnicate"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := cassette.Serve(t, tt.exchanges...)
			got := run(t, url, tt.stdin, tt.args...)
			if got.code != tt.code {
				t.Errorf("exit code %d, want %d\nstdout: %s\nstderr: %s", got.code, tt.code, got.stdout, got.stderr)
			}
			for _, want := range tt.stdout {
				if !strings.Contains(got.stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, got.stdout)
				}
			}
			for _, want := range tt.stderr {
				if !strings.Contains(got.stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, got.stderr)
				}
			}
		})
	}
}

func TestLogin(t *testing.T) {
	user := cassette.Load(t, "user")
	user.User = "alice@acme.test"
	url := cassette.Serve(t, user)
	got := run(t, url, "the-key\n", "login", "--org", "acme", "--user", "alice@acme.test")
	if got.code != 0 {
		t.Fatalf("exit code %d: %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "Logged in to "+url+" as alice@acme.test (acme, ADMIN)") {
		t.Errorf("stdout: %s", got.stdout)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cvedex", "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"key": "the-key"`) {
		t.Errorf("config: %s", data)
	}
}

func TestLoginFailures(t *testing.T) {
	tests := []struct {
		name      string
		exchanges []cassette.Exchange
		env       map[string]string
		stdin     string
		args      []string
		stderr    string
	}{
		{name: "no key", args: []string{"login"}, stderr: "no API key: pipe it on stdin"},
		{name: "test instance without an org", env: map[string]string{"CVE_API_ORG": ""}, stdin: "key\n",
			args: []string{"login", "--test"}, stderr: "missing --org"},
		{name: "no org or user", env: map[string]string{"CVE_API_ORG": "", "CVE_API_USER": ""}, stdin: "key\n",
			args: []string{"login"}, stderr: "missing --org and --user"},
		{name: "wrong key", exchanges: []cassette.Exchange{cassette.Load(t, "unauthorized")}, stdin: "key",
			args: []string{"login", "--user", "ada"}, stderr: "Check your credentials with cvedex status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := cassette.Serve(t, tt.exchanges...)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("CVE_API_URL", url)
			t.Setenv("CVE_API_ORG", "acme")
			t.Setenv("CVE_API_USER", "alice@acme.test")
			t.Setenv("CVE_API_KEY", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			var stdout, stderr bytes.Buffer
			code := cli.Main(context.Background(), tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tt.stderr) {
				t.Errorf("exit code %d, stderr %q, want 1 and %q", code, stderr.String(), tt.stderr)
			}
		})
	}
}

func TestNotLoggedIn(t *testing.T) {
	url := cassette.Serve(t, cassette.Load(t, "health-check"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", url)
	for _, name := range []string{"CVE_API_ORG", "CVE_API_USER", "CVE_API_KEY"} {
		t.Setenv(name, "")
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Main(context.Background(), []string{"status"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("status: exit code %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "not logged in, run cvedex login") {
		t.Errorf("status: %s", stdout.String())
	}
	if code := cli.Main(context.Background(), []string{"list"}, strings.NewReader(""), &stdout, &stderr); code != 1 {
		t.Errorf("list: exit code %d", code)
	}
	if !strings.Contains(stderr.String(), "Not logged in. Run cvedex login") {
		t.Errorf("list: %s", stderr.String())
	}
}

func TestSavedConfig(t *testing.T) {
	url := cassette.Serve(t, cassette.Load(t, "cve-id-list"))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, name := range []string{"CVE_API_URL", "CVE_API_ORG", "CVE_API_USER", "CVE_API_KEY"} {
		t.Setenv(name, "")
	}
	path := filepath.Join(home, ".config", "cvedex", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		config string
		code   int
		out    string
	}{
		{config: `{"url":"` + url + `","org":"acme","user":"alice@acme.test","key":"key"}`, out: "CVE-2026-1100"},
		{config: `{"url":`, code: 1, out: path + ": unexpected end of JSON input"},
		{config: "", code: 1, out: "read " + path},
	} {
		if tt.config == "" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, []byte(tt.config), 0o600); tt.config != "" && err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.Main(context.Background(), []string{"list"}, strings.NewReader(""), &stdout, &stderr)
		if code != tt.code || !strings.Contains(stdout.String()+stderr.String(), tt.out) {
			t.Errorf("exit code %d, output %q; want %d and %q", code, stdout.String()+stderr.String(), tt.code, tt.out)
		}
	}
}

// TestAPIErrors checks every command reports a failing server instead of carrying on.
func TestAPIErrors(t *testing.T) {
	failing := func(cvedexd bool) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cvedexd && r.URL.Path == "/api/health-check" {
				_, _ = io.WriteString(w, `{"server":"cvedexd","version":"0.1.0"}`)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"DOWN","message":"Out of service"}`)
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	plain, cvedexd := failing(false), failing(true)
	tests := []struct {
		url  string
		args []string
	}{
		{plain, []string{"status"}},
		{plain, []string{"list"}},
		{plain, []string{"org"}},
		{plain, []string{"org", "add-user", "bob@acme.test", "--first", "Bob", "--last", "Smith"}},
		{plain, []string{"org", "reset-key", "bob@acme.test", "--yes"}},
		{plain, []string{"review"}},
		{cvedexd, []string{"status"}},
		{cvedexd, []string{"review"}},
		{cvedexd, []string{"review", "show", "CVE-2026-1100"}},
		{cvedexd, []string{"review", "approve", "CVE-2026-1100"}},
		{cvedexd, []string{"review", "request-changes", "CVE-2026-1100", "Add a CWE."}},
		{cvedexd, []string{"proposals"}},
		{cvedexd, []string{"proposals", "approve", "p1"}},
		{cvedexd, []string{"proposals", "deny", "p1"}},
		{cvedexd, []string{"audit"}},
		{cvedexd, []string{"submitter", "add", "bob"}},
		{cvedexd, []string{"submitter", "token", "1"}},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got := run(t, tt.url, "", tt.args...)
			if got.code != 1 || !strings.Contains(got.stderr, "Out of service (DOWN)") {
				t.Errorf("exit code %d, stderr %q", got.code, got.stderr)
			}
		})
	}
}

func TestConfigErrors(t *testing.T) {
	for _, name := range []string{"HOME", "USERPROFILE", "home", "XDG_CONFIG_HOME"} {
		t.Setenv(name, "")
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Main(context.Background(), []string{"status"}, strings.NewReader(""), &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "not defined") {
		t.Errorf("without a home directory: exit code %d, stderr %q", code, stderr.String())
	}

	if runtime.GOOS == "windows" {
		t.Skip("Windows ignores directory permissions")
	}
	for _, readOnly := range []string{".", "cvedex"} {
		config := t.TempDir()
		if err := os.MkdirAll(filepath.Join(config, readOnly), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(config, readOnly), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", config)
		t.Setenv("CVE_API_URL", cassette.Serve(t, cassette.Load(t, "user")))
		t.Setenv("CVE_API_KEY", "")
		stderr.Reset()
		args := []string{"login", "--org", "acme", "--user", "alice@acme.test"}
		if code := cli.Main(context.Background(), args, strings.NewReader("key\n"), &stdout, &stderr); code != 1 ||
			!strings.Contains(stderr.String(), "permission denied") {
			t.Errorf("read-only %s: exit code %d, stderr %q", readOnly, code, stderr.String())
		}
	}
}

func TestMCP(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "key")
	stdin, input := io.Pipe()
	output, stdout := io.Pipe()
	code := make(chan int)
	go func() { code <- cli.Main(context.Background(), []string{"mcp"}, stdin, stdout, io.Discard) }()
	_, err := io.WriteString(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `"serverInfo":{"name":"cvedex"`) {
		t.Errorf("initialize: %s", line)
	}
	_ = input.Close()
	if c := <-code; c != 0 {
		t.Errorf("exit code %d", c)
	}
}

// terminal runs cvedex in a pseudo-terminal, for the prompts and the TUI.
type terminal struct {
	t      *testing.T
	pty    *os.File
	mu     sync.Mutex
	screen bytes.Buffer
	code   chan int
}

func startTerminal(t *testing.T, args ...string) *terminal {
	t.Helper()
	return startTerminalContext(t, context.Background(), args...)
}

func startTerminalContext(t *testing.T, ctx context.Context, args ...string) *terminal {
	t.Helper()
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	if err := pty.Setsize(tty, &pty.Winsize{Rows: 30, Cols: 120}); err != nil {
		t.Fatal(err)
	}
	term := &terminal{t: t, pty: ptmx, code: make(chan int, 1)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			term.mu.Lock()
			term.screen.Write(buf[:n])
			term.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		term.code <- cli.Main(ctx, args, tty, tty, tty)
		_ = tty.Close()
	}()
	return term
}

func (term *terminal) waitFor(text string) {
	term.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		term.mu.Lock()
		screen := ansi.Strip(term.screen.String())
		term.mu.Unlock()
		if strings.Contains(screen, text) {
			return
		}
		if time.Now().After(deadline) {
			term.t.Fatalf("terminal never showed %q:\n%s", text, screen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (term *terminal) send(keys string) {
	term.t.Helper()
	if _, err := term.pty.WriteString(keys); err != nil {
		term.t.Fatal(err)
	}
}

func (term *terminal) exits(code int) {
	term.t.Helper()
	select {
	case got := <-term.code:
		if got != code {
			term.t.Errorf("exit code %d, want %d", got, code)
		}
	case <-time.After(5 * time.Second):
		term.t.Fatal("cvedex did not exit")
	}
}

func loggedOut(t *testing.T, url string) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", url)
	for _, name := range []string{"CVE_API_ORG", "CVE_API_USER", "CVE_API_KEY"} {
		t.Setenv(name, "")
	}
}

func TestLoginForm(t *testing.T) {
	user := cassette.Load(t, "user")
	user.User = "alice@acme.test"
	url := cassette.Serve(t, user)
	loggedOut(t, url)
	term := startTerminal(t, "login")
	term.waitFor("> Another server")
	term.send("\r")
	term.waitFor("Server URL")
	// huh moves focus asynchronously, so each answer waits for the previous one to land.
	for _, answer := range []string{"", "", " acme", "alice@acme.test ", "the-key"} {
		time.Sleep(200 * time.Millisecond)
		term.send(answer + "\r")
	}
	term.waitFor("required")
	term.waitFor("Logged in to " + url + " as alice@acme.test (acme, ADMIN)")
	term.exits(0)
}

func TestLoginFormInterrupted(t *testing.T) {
	loggedOut(t, cveservices.TestURL)
	ctx, cancel := context.WithCancel(context.Background())
	term := startTerminalContext(t, ctx, "login", "--test")
	term.waitFor("CNA short name")
	cancel()
	term.waitFor("Error:")
	term.exits(1)
}

func TestLoginFormCancelled(t *testing.T) {
	loggedOut(t, cveservices.TestURL)
	term := startTerminal(t, "login", "--test")
	term.waitFor("CNA short name")
	term.send("\x03")
	term.waitFor("login cancelled")
	term.exits(1)
}

func TestConfirm(t *testing.T) {
	run := func(t *testing.T, exchanges []cassette.Exchange, args []string, answer, want string, code int) {
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		t.Setenv("CVE_API_URL", cassette.Serve(t, exchanges...))
		t.Setenv("CVE_API_ORG", "acme")
		t.Setenv("CVE_API_USER", "alice@acme.test")
		t.Setenv("CVE_API_KEY", "key")
		term := startTerminal(t, args...)
		term.waitFor("?")
		term.send(answer)
		term.waitFor(want)
		term.exits(code)
	}
	t.Run("yes", func(t *testing.T) {
		reset := cassette.Exchange{Method: "PUT", Path: "/api/org/acme/user/bob@acme.test/reset_secret",
			Response: `{"API-secret":"new-key"}`}
		run(t, []cassette.Exchange{reset}, []string{"org", "reset-key", "bob@acme.test"}, "y", "new-key", 0)
	})
	t.Run("no", func(t *testing.T) {
		run(t, nil, []string{"--url", cveservices.ProductionURL, "reject", "CVE-2026-1100", "--reason", "Unused."},
			"n", "cancelled", 1)
	})
}

func TestTerminalWidth(t *testing.T) {
	record := cassette.Load(t, "cve-2025-0001")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", cassette.Serve(t, record))
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "key")
	term := startTerminal(t, "show", "CVE-2025-0001")
	term.waitFor("References")
	term.exits(0)
}

func TestTUI(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", cassette.Serve(t, cassette.Load(t, "health-check"), cassette.Load(t, "cve-id-list")))
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "key")
	term := startTerminal(t, "tui")
	term.waitFor("CVE-2026-1100")
	term.send("q")
	term.exits(0)
}
