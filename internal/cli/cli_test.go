package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	} {
		if err := os.WriteFile(path, []byte(tt.config), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.Main(context.Background(), []string{"list"}, strings.NewReader(""), &stdout, &stderr)
		if code != tt.code || !strings.Contains(stdout.String()+stderr.String(), tt.out) {
			t.Errorf("exit code %d, output %q; want %d and %q", code, stdout.String()+stderr.String(), tt.code, tt.out)
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
