package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"github.com/zalando/go-keyring"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/cassette"
	"github.com/Kludex/cvedex/internal/cli"
	"github.com/Kludex/cvedex/internal/github"
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
	t.Setenv("GITHUB_API_URL", url)
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "key")
	return rerun(stdin, args...)
}

// rerun runs cvedex in the environment of the previous run, to see what it saved.
func rerun(stdin string, args ...string) result {
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
	empty := filepath.Join(dir, "empty.json")
	rejected := cassette.Load(t, "bad-request")
	rejected.Body = ""
	const advisoryURL = "https://github.com/Kludex/python-multipart/security/advisories/GHSA-59g5-xgcq-4qw3"
	for path, data := range map[string]string{
		empty:   "{}",
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
		`"action":"publish","revision":2,"previous":{"cnaContainer":{"title":"Traversal"}},"published":null,` +
		`"record":{"cnaContainer":{"title":"Path traversal in widget","x_hidden":"\u001b]0;pwned\u0007"}}}]}`
	reviewUpdate := `{"cves":[{"cve_id":"CVE-2026-1100","submitter":"bob","action":"reject","revision":3,` +
		`"previous":null,"published":{"cnaContainer":{"title":"Path traversal"}},` +
		`"record":{"cnaContainer":{"rejectedReasons":[{"lang":"en","value":"Duplicate."}]}}}]}`
	reviewNew := `{"cves":[{"cve_id":"CVE-2026-1100","submitter":"bob","action":"publish","revision":1,` +
		`"previous":null,"published":null,"record":{"cnaContainer":{"title":"Fresh"}}}]}`

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
			stderr: []string{"Waiting for approval as proposal p1", "cvedex proposals show p1"},
		},
		{
			name: "reserve through an agent token as JSON",
			exchanges: []cassette.Exchange{{Method: "POST", Path: "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
				Status: 202, Response: `{"proposal_id":"p1"}`}},
			args: []string{"reserve", "--year", "2026", "--json"},
			code: 1,
			stderr: []string{`{"error":"PENDING_APPROVAL","message":"waiting for approval as proposal p1",` +
				`"details":{"proposal_id":"p1"}}`},
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
			name:      "publish a record CVE Services rejects",
			exchanges: []cassette.Exchange{rejected},
			args:      []string{"publish", "CVE-2026-1100", bare},
			code:      1,
			stderr:    []string{"Error:", "INVALID_JSON_SCHEMA", "/cnaContainer"},
		},
		{
			name:  "publish a record that breaks the schema",
			args:  []string{"publish", "CVE-2026-1100", "-"},
			stdin: `{"descriptions":[{"lang":"en","value":"x"}],"affected":[],"references":[],"\u001b":1}`,
			code:  1,
			stderr: []string{"Error: the record on stdin is not a valid CNA container:\n",
				"  - /affected: minItems: got 0, want 1\n", `additional properties '\x1b' not allowed`},
		},
		{name: "update a file that breaks the schema", args: []string{"update", "CVE-2026-1100", empty}, code: 1,
			stderr: []string{"empty.json is not a valid CNA container:\n  - missing properties"}},
		{
			name:      "record from-advisory",
			exchanges: []cassette.Exchange{cassette.Load(t, "advisory")},
			args:      []string{"record", "from-advisory", advisoryURL},
			stdout: []string{`"title": "python-multipart: Denial of service (DoS) via deformation`, `"lessThan": "0.0.18"`,
				`"cweId": "CWE-770"`, `"cvssV3_1": {`, `"value": "defnull",`, `"advisory": "GHSA-59g5-xgcq-4qw3"`},
		},
		{
			name: "record from-advisory needs edits",
			exchanges: []cassette.Exchange{{Method: "GET", Path: cassette.Load(t, "advisory").Path,
				Response: `{"ghsa_id":"GHSA-59g5-xgcq-4qw3","html_url":"` + advisoryURL + `","description":""}`}},
			args:   []string{"record", "from-advisory", advisoryURL},
			stdout: []string{`"affected": null`},
			stderr: []string{"Edit it before you publish. It is not a valid CNA container:\n",
				"  - /descriptions/0/value: minLength: got 0, want 1"},
		},
		{name: "record from-advisory with another URL", args: []string{"record", "from-advisory", "https://acme.org"},
			code: 1, stderr: []string{"https://acme.org is not a GitHub repository advisory"}},
		{name: "publish a file that is not JSON", args: []string{"publish", "CVE-2026-1100", broken}, code: 1,
			stderr: []string{"broken.json is not a JSON object"}},
		{name: "publish a file that is not JSON, as JSON", args: []string{"publish", "CVE-2026-1100", broken, "--json"},
			code: 1, stderr: []string{`{"error":"CVEDEX_ERROR","message":"`, `broken.json is not a JSON object: `}},
		{name: "record check", args: []string{"record", "check", bare},
			stdout: []string{"The record is a valid CNA container"}},
		{name: "record check as JSON", args: []string{"record", "check", "--json", "-"}, stdin: string(sent.CNA),
			stdout: []string{`"valid": true`}},
		{
			name:  "record check an invalid record as JSON",
			args:  []string{"record", "check", "--json", "-"},
			stdin: "{}",
			code:  1,
			stderr: []string{`{"error":"INVALID_RECORD","message":"the record on stdin is not a valid CNA container",` +
				`"details":{"problems":["- missing properties 'descriptions', 'affected', 'references'"]}}`},
		},
		{
			name:   "publish a missing file",
			args:   []string{"publish", "CVE-2026-1100", filepath.Join(dir, "missing.json")},
			code:   1,
			stderr: []string{"missing.json"},
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
			name:      "reject",
			exchanges: []cassette.Exchange{cassette.Load(t, "cve-id-reserved"), cassette.Load(t, "reject")},
			args:      []string{"reject", "CVE-2026-1107", "--reason", "cvedex fixture recording. Not a real ID."},
			stdout:    []string{"Rejected CVE-2026-1107", "REJECTED"},
		},
		{
			name: "reject a published ID",
			exchanges: []cassette.Exchange{
				cassette.Load(t, "cve-id-published"),
				cassette.Load(t, "reject-published"),
			},
			args:   []string{"reject", "CVE-2026-1108", "--reason", "cvedex fixture recording. Not a real ID."},
			stdout: []string{"Rejected CVE-2026-1108", "REJECTED"},
		},
		{
			name: "reject an unknown ID",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve-id/CVE-2026-9", Status: 404,
				Response: `{"error":"CVEID_NOT_FOUND","message":"The CVE ID does not exist."}`}},
			args:   []string{"reject", "CVE-2026-9", "--reason", "Duplicate."},
			code:   1,
			stderr: []string{"(CVEID_NOT_FOUND)"},
		},
		{
			name:   "reject without a reason",
			args:   []string{"reject", "CVE-2026-1100"},
			code:   1,
			stderr: []string{"--reason is required"},
		},
		{
			name:      "reject only the ID",
			exchanges: []cassette.Exchange{cassette.Load(t, "id-state-rejected")},
			args:      []string{"reject", "CVE-2026-1107", "--id-only"},
			stdout:    []string{"CVE-2026-1107 is REJECTED", "cvedex list --state rejected"},
		},
		{
			name:      "unreject",
			exchanges: []cassette.Exchange{cassette.Load(t, "id-state-reserved")},
			args:      []string{"unreject", "2026-1107", "--json"},
			stdout:    []string{`"state": "RESERVED"`},
		},
		{
			name:   "unreject on production without a terminal",
			args:   []string{"unreject", "CVE-2026-1107", "--url", "https://cveawg.mitre.org"},
			code:   1,
			stderr: []string{"unreject needs --yes"},
		},
		{
			name: "unreject an ID that was not rejected",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/cve-id/CVE-2026-1107?state=RESERVED", Status: 400,
				Response: `{"error":"BAD_INPUT","message":"Bad state"}`}},
			args:   []string{"unreject", "CVE-2026-1107"},
			code:   1,
			stderr: []string{"Bad state (BAD_INPUT)"},
		},
		{
			name:      "adp without the ADP role",
			exchanges: []cassette.Exchange{cassette.Load(t, "adp-forbidden")},
			args:      []string{"adp", "CVE-2026-1108", "-"},
			stdin:     `{"adpContainer":{"title":"cvedex fixture recording"}}`,
			code:      1,
			stderr:    []string{"This function is only allowed for ADPs. (ADP_ONLY)"},
		},
		{
			name: "adp",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/cve/CVE-2026-1108/adp",
				Body:     `{"adpContainer":{"title":"Enriched"}}`,
				Response: `{"updated":{"cveMetadata":{"cveId":"CVE-2026-1108","state":"PUBLISHED"}}}`}},
			args:   []string{"adp", "CVE-2026-1108", "-"},
			stdin:  `{"title":"Enriched"}`,
			stdout: []string{"Updated CVE-2026-1108"},
		},
		{name: "adp a file that is not JSON", args: []string{"adp", "CVE-2026-1108", broken}, code: 1,
			stderr: []string{"broken.json is not a JSON object"}},
		{name: "adp a missing file", args: []string{"adp", "CVE-2026-1108", filepath.Join(dir, "missing.json")},
			code: 1, stderr: []string{"missing.json"}},
		{
			name:      "org",
			exchanges: []cassette.Exchange{cassette.Load(t, "org")},
			args:      []string{"org"},
			stdout:    []string{"acme", "Roles", "ID quota"},
		},
		{
			name:      "org quota",
			exchanges: []cassette.Exchange{cassette.Load(t, "id-quota")},
			args:      []string{"org", "quota"},
			stdout:    []string{"Quota", "1000", "Reserved", "2", "Available", "998"},
		},
		{
			name: "org quota failing",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/org/acme/id_quota", Status: 500,
				Response: `{"message":"Quota lookup failed"}`}},
			args:   []string{"org", "quota"},
			code:   1,
			stderr: []string{"Quota lookup failed"},
		},
		{
			name:      "org update-user",
			exchanges: []cassette.Exchange{cassette.Load(t, "user-update")},
			args:      []string{"org", "update-user", "alice@acme.test", "--first", "acme"},
			stdout:    []string{"Updated alice@acme.test"},
		},
		{
			name: "org update-user deactivates and drops the admin role",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/org/acme/user/bob@acme.test?active=false&" +
				"active_roles.remove=ADMIN&name.last=Jones&new_username=robert@acme.test",
				Response: `{"updated":{"username":"robert@acme.test"}}`}},
			args: []string{"org", "update-user", "bob@acme.test", "--active=false", "--admin=false", "--last", "Jones",
				"--username", "robert@acme.test"},
			stdout: []string{"Updated robert@acme.test"},
		},
		{
			name: "org update-user with a new username",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/org/acme/user/bob%40acme.test?new_username=" +
				"robert%40acme.test", Response: `{"updated":{"username":"robert@acme.test"}}`}},
			args:   []string{"org", "update-user", "bob@acme.test", "--username", "robert@acme.test", "--json"},
			stdout: []string{`"username": "robert@acme.test"`},
		},
		{
			name: "org update-user makes an admin",
			exchanges: []cassette.Exchange{{Method: "PUT", Path: "/api/org/acme/user/bob@acme.test?active=true&" +
				"active_roles.add=ADMIN", Status: 403, Response: `{"error":"NOT_ORG_ADMIN","message":"Admins only."}`}},
			args:   []string{"org", "update-user", "bob@acme.test", "--active", "--admin"},
			code:   1,
			stderr: []string{"Admins only. (NOT_ORG_ADMIN)"},
		},
		{name: "org update-user without changes", args: []string{"org", "update-user", "bob@acme.test"}, code: 1,
			stderr: []string{"nothing to change"}},
		{
			name: "list filtered",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve-id?cve_id_year=2026&" +
				"time_modified.lt=2026-10-31T12%3A00%3A00Z&time_reserved.gt=2026-01-01T00%3A00%3A00Z",
				Response: `{"cve_ids":[{"cve_id":"CVE-2026-1"}]}`}},
			args: []string{"list", "--year", "2026", "--reserved-after", "2026-01-01",
				"--modified-before", "2026-10-31T12:00:00Z"},
			stdout: []string{"CVE-2026-1"},
		},
		{name: "list from a bad date", args: []string{"list", "--modified-after", "yesterday"}, code: 1,
			stderr: []string{`"yesterday" is not a date such as 2026-10-31`}},
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
			stdout:    []string{"CVE-2026-1100", "publish", "2", "bob", "2026-10-22", "Path traversal in widget"},
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
			stdout: []string{"CVE-2026-1100", "revision 2 from bob, asking to publish", "Path traversal in widget",
				"Changes since the revision before", `-    "title": "Traversal"`,
				`+    "title": "Path traversal in widget"`, "Full record", `"x_hidden": "\u001b]0;pwned\u0007"`,
				"cvedex review approve CVE-2026-1100 --revision 2"},
		},
		{
			name:      "review show an update",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: reviewUpdate}),
			args:      []string{"review", "show", "2026-1100"},
			stdout: []string{"revision 3 from bob, asking to reject", "Changes from the published record",
				`-    "title": "Path traversal"`, `+    "rejectedReasons": [`},
		},
		{
			name:      "review show a first revision",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: reviewNew}),
			args:      []string{"review", "show", "2026-1100"},
			stdout:    []string{"revision 1 from bob", "Full record"},
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
				Body: `{"revision":2}`, Response: `{"created":{"cveMetadata":{"cveId":"CVE-2026-1100","state":"PUBLISHED"}}}`}),
			args:   []string{"review", "approve", "CVE-2026-1100", "--revision", "2"},
			stdout: []string{"Approved CVE-2026-1100", "PUBLISHED"},
		},
		{
			name: "review approve a changed record",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/approve",
				Body: `{"revision":1}`, Status: 409,
				Response: `{"error":"STALE_REVISION","message":"CVE-2026-1100 changed since revision 1"}`}),
			args:   []string{"review", "approve", "CVE-2026-1100", "--revision", "1"},
			code:   1,
			stderr: []string{"(STALE_REVISION)"},
		},
		{
			name: "review request-changes",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/request-changes",
				Body:     `{"note":"Add the CWE.","revision":2}`,
				Response: `{"cve_id":"CVE-2026-1100","state":"reserved","note":"Add the CWE."}`}),
			args:   []string{"review", "request-changes", "CVE-2026-1100", "Add the CWE.", "--revision", "2"},
			stdout: []string{"Sent CVE-2026-1100 back to its submitter."},
		},
		{
			name: "proposals",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
					`{"id":"p1","method":"POST","path":"/api/cve-id?amount=1","body":null,"created_at":"2026-10-22T10:00:00Z"}]}`},
			),
			args:   []string{"proposals"},
			stdout: []string{"p1", "POST /api/cve-id?amount=1", "2026-10-22", "cvedex proposals show <id>"},
		},
		{
			name: "proposals show",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
					`{"id":"p1","method":"POST","path":"/api/cve-id?amount=1","body":null,"created_at":"2026-10-22T10:00:00Z"},` +
					`{"id":"p2","method":"POST","path":"/api/cve/CVE-2026-1/cna",` +
					`"body":"{\"cnaContainer\":{\"title\":\"Overflow\"}}","created_at":"2026-10-22T11:00:00Z"}]}`},
			),
			args:   []string{"proposals", "show", "p2"},
			stdout: []string{"POST /api/cve/CVE-2026-1/cna", "proposed 2026-10-22", `"title": "Overflow"`},
		},
		{
			name: "proposals show a body that is not JSON",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
					`{"id":"p1","method":"POST","path":"/api/cve-id","body":"not json\u001b[2J"}]}`},
			),
			args:   []string{"proposals", "show", "p1"},
			stdout: []string{`not json\x1b[2J`},
		},
		{
			name: "proposals show one not pending",
			exchanges: cvedexd(
				cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
			),
			args:   []string{"proposals", "show", "p9"},
			code:   1,
			stderr: []string{"no pending proposal p9"},
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
					Path:   "/api/cvedexd/audit?before=9&since=2026-01-01&user=bob",
					Response: `{"next":1,"audit":[` +
						`{"id":3,"ts":"2026-10-22T10:00:00.000Z","actor":"bob","actor_kind":"agent",` +
						`"method":"POST","path":"/api/cve-id","status":202},` +
						`{"id":2,"ts":"2026-10-22T10:01:00.000Z","actor":"bob","actor_kind":"user",` +
						`"method":"GET","path":"/api/cve-id","status":403},` +
						`{"id":1,"ts":"2026-10-22T10:02:00.000Z","actor":"bob","actor_kind":"user",` +
						`"method":"GET","path":"/api/cve-id","status":null}]}`,
				},
			),
			args: []string{"audit", "--user", "bob", "--since", "2026-01-01", "--before", "9"},
			stdout: []string{"2026-10-22 10:00:00", "bob", "agent", "POST /api/cve-id", "202", "403", "?",
				"Older entries: cvedex audit --before 1"},
		},
		{
			name: "submitter list",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/submitters",
				Response: `{"submitters":[{"id":1,"name":"bob","created_at":"2026-10-01T00:00:00Z","disabled_at":null,` +
					`"open_ids":2,"tokens":1},{"id":2,"name":"eve","created_at":"2026-10-02T00:00:00Z",` +
					`"disabled_at":"2026-10-03T00:00:00Z","open_ids":0,"tokens":0}]}`}),
			args:   []string{"submitter"},
			stdout: []string{"OPEN IDS", "bob", "enabled", "2026-10-01", "eve", "disabled"},
		},
		{
			name: "submitter list empty",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/submitters",
				Response: `{"submitters":[]}`}),
			args:   []string{"submitter"},
			stdout: []string{"No submitters. Add one with cvedex submitter add <name>."},
		},
		{
			name: "submitter list forbidden",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/submitters", Status: 403,
				Response: `{"error":"NOT_ALLOWED","message":"CNA users only"}`}),
			args:   []string{"submitter"},
			code:   1,
			stderr: []string{"CNA users only"},
		},
		{
			name: "submitter disable",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/submitters/2/disable",
				Response: `{"id":2,"name":"eve","disabled_at":"2026-10-03T00:00:00Z"}`}),
			args:   []string{"submitter", "disable", "2"},
			stdout: []string{"eve is disabled."},
		},
		{
			name: "submitter enable",
			exchanges: cvedexd(cassette.Exchange{Method: "POST", Path: "/api/cvedexd/submitters/2/enable", Status: 404,
				Response: `{"error":"SUBMITTER_NOT_FOUND","message":"No such submitter"}`}),
			args:   []string{"submitter", "enable", "2"},
			code:   1,
			stderr: []string{"(SUBMITTER_NOT_FOUND)"},
		},
		{name: "submitter enable a bad ID", exchanges: cvedexd(), args: []string{"submitter", "enable", "eve"},
			code: 1, stderr: []string{`submitter ID must be a number, not "eve"`}},
		{
			name: "submitter tokens",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/submitters/1/tokens",
				Response: `{"tokens":[{"id":4,"kind":"agent","created_at":"2026-10-01T00:00:00Z",` +
					`"last_used_at":"2026-10-05T00:00:00Z","revoked_at":"2026-10-06T00:00:00Z"},` +
					`{"id":5,"kind":"user","created_at":"2026-10-07T00:00:00Z","last_used_at":null,"revoked_at":null}]}`}),
			args:   []string{"submitter", "tokens", "1"},
			stdout: []string{"LAST USED", "4", "agent", "2026-10-01", "2026-10-05", "2026-10-06"},
		},
		{
			name: "submitter tokens failing",
			exchanges: cvedexd(cassette.Exchange{Method: "GET", Path: "/api/cvedexd/submitters/1/tokens", Status: 404,
				Response: `{"error":"SUBMITTER_NOT_FOUND","message":"No such submitter"}`}),
			args:   []string{"submitter", "tokens", "1"},
			code:   1,
			stderr: []string{"(SUBMITTER_NOT_FOUND)"},
		},
		{name: "submitter tokens of a bad ID", exchanges: cvedexd(), args: []string{"submitter", "tokens", "bob"},
			code: 1, stderr: []string{`submitter ID must be a number, not "bob"`}},
		{
			name: "submitter revoke",
			exchanges: cvedexd(cassette.Exchange{Method: "DELETE", Path: "/api/cvedexd/tokens/4",
				Response: `{"id":4,"kind":"agent","revoked_at":"2026-10-06T00:00:00Z"}`}),
			args:   []string{"submitter", "revoke", "4"},
			stdout: []string{"Revoked token 4."},
		},
		{
			name: "submitter revoke failing",
			exchanges: cvedexd(cassette.Exchange{Method: "DELETE", Path: "/api/cvedexd/tokens/4", Status: 404,
				Response: `{"error":"NOT_FOUND","message":"No such token"}`}),
			args:   []string{"submitter", "revoke", "4"},
			code:   1,
			stderr: []string{"No such token"},
		},
		{name: "submitter revoke a bad ID", exchanges: cvedexd(), args: []string{"submitter", "revoke", "four"},
			code: 1, stderr: []string{`token ID must be a number, not "four"`}},
		{
			name: "show a record with terminal escapes",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve/CVE-2026-1300", Response: `{` +
				`"cveMetadata":{"cveId":"CVE-2026-1300","state":"PUBLISHED"},"containers":{"cna":{` +
				`"title":"\u001b]0;pwned\u0007Overflow\u202e","references":[{"url":"https://x\u001b[8m.test"}]}}}`}},
			args:   []string{"show", "2026-1300"},
			stdout: []string{`\x1b]0;pwned\x07Overflow\u202e`, `https://x\x1b[8m.test`},
		},
		{
			name: "error with terminal escapes",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/api/cve/CVE-2026-1300", Status: 500,
				Response: `{"message":"\u001b[2Jgone"}`}},
			args:   []string{"show", "2026-1300"},
			code:   1,
			stderr: []string{`Error: \x1b[2Jgone`},
		},
		{
			name:   "plain HTTP",
			args:   []string{"list", "--url", "http://cve.example"},
			code:   1,
			stderr: []string{"http://cve.example would send your API key unencrypted; use https://"},
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

func TestMain(m *testing.M) {
	keyring.MockInit()
	github.Interval = time.Millisecond
	os.Exit(m.Run())
}

func TestLogin(t *testing.T) {
	user := cassette.Load(t, "user")
	user.User = "alice@acme.test"
	for _, tt := range []struct {
		name     string
		keychain error
		saved    string
		inFile   bool
	}{
		{name: "keychain", saved: "with the API key in the system keychain"},
		{name: "no keychain", keychain: errors.New("no keychain"), saved: "There is no system keychain",
			inFile: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keychain != nil {
				keyring.MockInitWithError(tt.keychain)
				t.Cleanup(keyring.MockInit)
			}
			url := cassette.Serve(t, user, cassette.Load(t, "cve-id-list"))
			got := run(t, url, "the-key\n", "login", "--org", "acme", "--user", "alice@acme.test")
			if got.code != 0 {
				t.Fatalf("exit code %d: %s", got.code, got.stderr)
			}
			if want := "Logged in to " + url + " as alice@acme.test (acme, ADMIN)"; !strings.Contains(got.stdout, want) ||
				!strings.Contains(got.stdout, tt.saved) {
				t.Errorf("stdout: %s", got.stdout)
			}
			path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cvedex", "config.json")
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
				t.Errorf("config mode %v, want 0600", info.Mode().Perm())
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), `"key": "the-key"`) != tt.inFile {
				t.Errorf("config: %s", data)
			}

			t.Setenv("CVE_API_KEY", "")
			var stdout, stderr bytes.Buffer
			if code := cli.Main(context.Background(), []string{"list"}, strings.NewReader(""), &stdout,
				&stderr); code != 0 || !strings.Contains(stdout.String(), "CVE-2026-1100") {
				t.Errorf("list with the saved key: exit code %d, %s%s", code, stdout.String(), stderr.String())
			}

			for _, want := range []string{"Logged out of " + url + " as alice@acme.test.", "You were not logged in."} {
				if got := rerun("", "logout"); got.code != 0 || !strings.Contains(got.stdout, want) {
					t.Errorf("logout: exit code %d, %s%s; want %q", got.code, got.stdout, got.stderr, want)
				}
			}
			if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("config still there: %v", err)
			}
			if _, err := keyring.Get("cvedex", "alice@acme.test on "+url); tt.keychain == nil &&
				!errors.Is(err, keyring.ErrNotFound) {
				t.Errorf("key still in the keychain: %v", err)
			}
		})
	}
}

func TestAccounts(t *testing.T) {
	user := cassette.Load(t, "user")
	user.User = "alice@acme.test"
	first, second := cassette.Serve(t, user), cassette.Serve(t, user)
	loggedOut(t, "")
	if got := rerun("", "accounts"); got.code != 0 || !strings.Contains(got.stdout, "You are not logged in.") {
		t.Errorf("accounts when logged out: exit code %d, %s%s", got.code, got.stdout, got.stderr)
	}
	for _, url := range []string{first, second} {
		if got := rerun("the-key\n", "--url", url, "login", "--org", "acme", "--user", "alice@acme.test"); got.code != 0 {
			t.Fatalf("login to %s: exit code %d, %s", url, got.code, got.stderr)
		}
	}
	for _, url := range []string{first, second} {
		if key, err := keyring.Get("cvedex", "alice@acme.test on "+url); key != "the-key" {
			t.Errorf("the key for %s is %q, %v", url, key, err)
		}
	}
	// Accounts are numbered by URL, whichever is in use.
	number := map[bool]string{true: "1", false: "2"}
	for _, tt := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"accounts"}, 0, number[second < first] + "   " + second + "   alice@acme.test   acme   in use\n"},
		{[]string{"accounts"}, 0, number[first < second] + "   " + first + "   alice@acme.test   acme\n"},
		{[]string{"accounts", "--json"}, 0, `"active": true`},
		{[]string{"accounts", "switch", "3"}, 1, "there is no account 3, see cvedex accounts"},
		{[]string{"accounts", "switch", "first"}, 1, `account ID must be a number, not "first"`},
		{[]string{"accounts", "switch", number[first < second]}, 0, "Now using " + first + " as alice@acme.test."},
		{[]string{"accounts"}, 0, first + "   alice@acme.test   acme   in use\n"},
		{[]string{"logout"}, 0, "Logged out of " + first + " as alice@acme.test.\nNow using " + second + " as"},
		{[]string{"logout", "--json"}, 0, `"url": "` + second + `"`},
		{[]string{"accounts"}, 0, "You are not logged in."},
	} {
		got := rerun("", tt.args...)
		output := got.stdout + got.stderr
		if got.code != tt.code || !strings.Contains(output, tt.want) || strings.Contains(output, "the-key") {
			t.Errorf("%v: exit code %d, %s%s; want %d and %q", tt.args, got.code, got.stdout, got.stderr, tt.code, tt.want)
		}
	}
	for _, url := range []string{first, second} {
		if _, err := keyring.Get("cvedex", "alice@acme.test on "+url); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("the key for %s is still in the keychain: %v", url, err)
		}
	}
}

func TestKeychainUnreadable(t *testing.T) {
	keyring.MockInitWithError(errors.New("keychain is locked"))
	t.Cleanup(keyring.MockInit)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", "https://cve.example")
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice@acme.test")
	t.Setenv("CVE_API_KEY", "")
	var stdout, stderr bytes.Buffer
	code := cli.Main(context.Background(), []string{"list"}, strings.NewReader(""), &stdout, &stderr)
	if want := "reading your API key from the system keychain: keychain is locked"; code != 1 ||
		!strings.Contains(stderr.String(), want) {
		t.Errorf("exit code %d, stderr %q; want 1 and %q", code, stderr.String(), want)
	}

	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cvedex", "config.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"url":"https://cve.example","user":"alice@acme.test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := rerun("", "logout")
	if want := "removing your API key from the system keychain: keychain is locked"; got.code != 1 ||
		!strings.Contains(got.stderr, want) {
		t.Errorf("logout: exit code %d, stderr %q; want 1 and %q", got.code, got.stderr, want)
	}
}

func TestLoginAsSubmitter(t *testing.T) {
	forbidden := cassette.Exchange{Method: "GET", Path: "/api/org/acme/user/bob", Status: 403,
		Response: `{"error":"NOT_ALLOWED","message":"Submitters can only reserve IDs and submit records"}`}
	exchanges := append([]cassette.Exchange{forbidden}, cvedexd()...)
	got := run(t, cassette.Serve(t, exchanges...), "token\n", "login", "--org", "acme", "--user", "bob")
	if got.code != 0 || !strings.Contains(got.stdout, "as bob (acme, submitter)") {
		t.Errorf("exit code %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
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
		{name: "forbidden by CVE Services", stdin: "key", args: []string{"login", "--user", "bob"},
			exchanges: []cassette.Exchange{
				{Method: "GET", Path: "/api/org/acme/user/bob", Status: 403, Response: `{"message":"Not yours"}`},
				cassette.Load(t, "health-check"),
			},
			stderr: "Not yours"},
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
	stderr.Reset()
	code := cli.Main(context.Background(), []string{"list", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Errorf("list --json: exit code %d", code)
	}
	if got := stderr.String(); got != `{"error":"NOT_LOGGED_IN","message":"not logged in"}`+"\n" {
		t.Errorf("list --json: %s", got)
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
		{cvedexd, []string{"review", "approve", "CVE-2026-1100", "--revision", "1"}},
		{cvedexd, []string{"review", "request-changes", "CVE-2026-1100", "Add a CWE.", "--revision", "1"}},
		{cvedexd, []string{"proposals"}},
		{cvedexd, []string{"proposals", "show", "p1"}},
		{cvedexd, []string{"submitter", "disable", "1"}},
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

// raceEnabled is set by race_test.go.
var raceEnabled bool

func startTerminalContext(t *testing.T, ctx context.Context, args ...string) *terminal {
	t.Helper()
	if raceEnabled {
		// muesli/cancelreader v0.2.2 closes its pipe while its reader still uses it, on every exit.
		t.Skip("bubbletea's input reader races on exit; CI runs these without -race")
	}
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
	// tty stays open: bubbletea's input reader may still touch it after cli.Main returns.
	go func() { term.code <- cli.Main(ctx, args, tty, tty, tty) }()
	return term
}

func (term *terminal) waitFor(text string) {
	term.t.Helper()
	term.waitAfter(0, text)
}

// answer sends keys, then waits for text among what the terminal shows from then on.
func (term *terminal) answer(keys, text string) {
	term.t.Helper()
	term.mu.Lock()
	at := term.screen.Len()
	term.mu.Unlock()
	term.send(keys)
	term.waitAfter(at, text)
}

func (term *terminal) waitAfter(at int, text string) {
	term.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		term.mu.Lock()
		screen := ansi.Strip(term.screen.String()[at:])
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
	// huh moves focus asynchronously, so each answer waits for the next group or empty field to show.
	const focused = "┃ >  "
	term.answer("\r", "Server URL")
	term.answer("\x15http://cve.example\r", "use https://")
	term.answer("\x15"+url+"\r", "CNA short name")
	term.answer("\r", "required")
	term.answer(" acme\r", focused)
	term.answer("alice@acme.test \r", focused)
	term.send("the-key\r")
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

const repoURL = "https://github.com/acme/cves"

// runRepo runs cvedex against the acme/cves repository on GitHub, with exchanges as GitHub's API.
// The exchanges are written after the examples of GitHub's OpenAPI description, not recorded.
func runRepo(t *testing.T, stdin string, exchanges []cassette.Exchange, args ...string) result {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CVE_API_URL", repoURL)
	t.Setenv("GITHUB_API_URL", cassette.Serve(t, exchanges...))
	t.Setenv("GH_TOKEN", "gh-token")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("CVE_API_ORG", "acme")
	t.Setenv("CVE_API_USER", "alice")
	t.Setenv("CVE_API_KEY", "cve-services-key")
	return rerun(stdin, args...)
}

// contents is a file as GitHub's contents API answers it.
func contents(text, sha string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	return `{"type":"file","encoding":"base64","sha":"` + sha + `","content":"` + encoded[:len(encoded)/2] + `\n` +
		encoded[len(encoded)/2:] + `\n"}`
}

func TestRepository(t *testing.T) {
	const (
		repo   = "/repos/acme/cves"
		record = `{"title":"Path traversal in widget","descriptions":[{"lang":"en","value":"widget before 1.4.2 ` +
			`serves files outside its root."}],"affected":[{"vendor":"acme","product":"widget","versions":[{"version":"0",` +
			`"lessThan":"1.4.2","status":"affected","versionType":"semver"}]}],"references":[{"url":"https://acme.test/1"}]}`
		untitled = `{"descriptions":[{"lang":"en","value":"widget serves files outside its root."}],"affected":` +
			`[{"vendor":"acme","product":"widget","versions":[{"version":"0","status":"affected"}]}],` +
			`"references":[{"url":"https://acme.test/1"}]}`
	)
	dir := t.TempDir()
	titled, bare := filepath.Join(dir, "titled.json"), filepath.Join(dir, "bare.json")
	for path, data := range map[string]string{titled: record, bare: untitled} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	committed := func(text string) string {
		var indented bytes.Buffer
		if err := json.Indent(&indented, []byte(text), "", "  "); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(append(indented.Bytes(), '\n'))
	}
	get := func(path, response string) cassette.Exchange {
		return cassette.Exchange{Method: "GET", Path: repo + path, Response: response}
	}
	missing := func(path string) cassette.Exchange {
		return cassette.Exchange{Method: "GET", Path: repo + path, Status: 404, Response: `{"message":"Not Found"}`}
	}
	info := get("", `{"default_branch":"main","permissions":{"admin":true,"push":true,"pull":true}}`)
	me := cassette.Exchange{Method: "GET", Path: "/user", Response: `{"login":"alice"}`}
	pull := func(number int, state, id, sha string) string {
		return fmt.Sprintf(`{"number":%[1]d,"state":%[2]q,"html_url":"https://github.com/acme/cves/pull/%[1]d",`+
			`"user":{"login":"bob"},"head":{"ref":"cve/%[3]s","sha":%[4]q},"created_at":"2026-10-2%[1]dT10:00:00Z",`+
			`"updated_at":"2026-10-22T11:00:00Z","commits":2}`, number, state, id, sha)
	}
	open := func(id, pulls string) cassette.Exchange {
		return get("/pulls?per_page=100&state=open&head=acme:cve/"+id, "["+pulls+"]")
	}
	const reviews = "/reviews?per_page=100"
	dispatch := cassette.Exchange{Method: "POST", Path: repo + "/actions/workflows/cvedex-reserve.yml/dispatches",
		Body:     `{"ref":"main","return_run_details":true,"inputs":{"year":"2026","count":"2","sequential":"true"}}`,
		Response: `{"workflow_run_id":7,"run_url":"https://api.github.com/repos/acme/cves/actions/runs/7"}`}
	running := get("/actions/runs/7", `{"id":7,"status":"in_progress","conclusion":null}`)
	ran := func(conclusion string) cassette.Exchange {
		return get("/actions/runs/7", `{"id":7,"status":"completed","conclusion":"`+conclusion+`","head_sha":"abc",`+
			`"html_url":"https://github.com/acme/cves/actions/runs/7"}`)
	}
	jobs := get("/actions/runs/7/jobs", `{"total_count":1,"jobs":[{"id":70,"name":"reserve"}]}`)
	branch := func(id, sha string, status int) cassette.Exchange {
		return cassette.Exchange{Method: "POST", Path: repo + "/git/refs", Status: status,
			Body: `{"ref":"refs/heads/cve/` + id + `","sha":"` + sha + `"}`, Response: `{"ref":"refs/heads/cve/` + id + `"}`}
	}
	// log is a job's log the way GitHub serves the one of a real run of the reserve workflow.
	log := func(ids ...string) string {
		text := "2026-11-19T13:46:17.1550181Z \x1b[36;1mjq -r '.[] | \"::notice title=cvedex::\\(.cve_id)\"' " +
			"ids.json\x1b[0m\n" +
			"2026-11-19T13:46:17.1890000Z ##[notice]Runners are busy.\n"
		for _, id := range ids {
			text += "2026-11-19T13:46:17.5198660Z ##[notice]" + id + "\r\n"
		}
		return text + "2026-11-19T13:46:17.5310000Z Cleaning up orphan processes\n"
	}
	reserve := []string{"reserve", "--year", "2026", "--count", "2", "--sequential"}
	approve := []string{"review", "approve", "CVE-2026-1101", "--revision", "2"}
	merge := cassette.Exchange{Method: "PUT", Path: repo + "/pulls/4/merge", Body: `{"sha":"s4","merge_method":"squash"}`,
		Response: `{"sha":"m1","merged":true,"message":"Pull Request successfully merged"}`}
	approved := cassette.Exchange{Method: "POST", Path: repo + "/pulls/4/reviews",
		Body: `{"event":"APPROVE","commit_id":"s4"}`, Response: `{"id":80,"state":"APPROVED"}`}
	const published = "/actions/workflows/cvedex-publish.yml/runs?head_sha=m1"
	var hundred []string
	for i := range 100 {
		hundred = append(hundred, fmt.Sprintf(`{"run_number":%d,"status":"queued"}`, i))
	}

	tests := []struct {
		name      string
		exchanges []cassette.Exchange
		args      []string
		code      int
		stdout    []string
		stderr    []string
	}{
		{
			name:      "status",
			exchanges: []cassette.Exchange{me, info},
			args:      []string{"status"},
			stdout:    []string{repoURL, "cvedexd on GitHub", "alice admin"},
		},
		{
			name: "reserve",
			exchanges: []cassette.Exchange{info, dispatch, running, ran("success"), jobs,
				missing("/actions/jobs/70/logs"), get("/actions/jobs/70/logs", log("CVE-2026-1200", "CVE-2026-1201")),
				branch("CVE-2026-1200", "abc", 201), branch("CVE-2026-1201", "abc", 422)},
			args:   reserve,
			stdout: []string{"Reserved 2 CVE IDs", "CVE-2026-1200", "CVE-2026-1201"},
		},
		{
			name:      "reserve when the workflow fails",
			exchanges: []cassette.Exchange{info, dispatch, ran("failure")},
			args:      reserve,
			code:      1,
			stderr:    []string{"The reserve workflow failed: https://github.com/acme/cves/actions/runs/7 (WORKFLOW_FAILED)"},
		},
		{
			name:      "reserve when the workflow reserves nothing",
			exchanges: []cassette.Exchange{info, dispatch, ran("success"), jobs, get("/actions/jobs/70/logs", log())},
			args:      reserve,
			code:      1,
			stderr:    []string{"The reserve workflow reserved no ID: https://github.com/acme/cves/actions/runs/7"},
		},
		{
			name:      "reserve when the workflow never ends",
			exchanges: append([]cassette.Exchange{info, dispatch}, slices.Repeat([]cassette.Exchange{running}, 150)...),
			args:      reserve,
			code:      1,
			stderr:    []string{"The reserve workflow has not finished yet. See https://github.com/acme/cves/actions"},
		},
		{
			name: "list",
			exchanges: []cassette.Exchange{info,
				get("/git/trees/main?recursive=1", `{"tree":[{"path":"README.md","type":"blob"},{"path":"records","type":"tree"},`+
					`{"path":"records/CVE-2026-1100.json","type":"blob"},{"path":"records/notes.txt","type":"blob"}]}`),
				get("/git/matching-refs/heads/cve/", `[`+
					`{"ref":"refs/heads/cve/CVE-2026-1100"},{"ref":"refs/heads/cve/CVE-2026-1101"},`+
					`{"ref":"refs/heads/cve/CVE-2026-1102"},{"ref":"refs/heads/cve/CVE-2026-1103"},{"ref":"refs/heads/cve/draft"}]`),
				get("/pulls?per_page=100&state=all", "["+pull(5, "open", "CVE-2026-1102", "s5")+","+
					pull(4, "open", "CVE-2026-1101", "s4")+","+pull(3, "closed", "CVE-2026-1100", "s3")+","+
					pull(2, "closed", "CVE-2025-0009", "s2")+","+pull(1, "open", "draft", "s1")+"]"),
				get("/pulls/5"+reviews, `[{"state":"CHANGES_REQUESTED","body":"Add the CWE.","commit_id":"s5"},`+
					`{"state":"COMMENTED","body":"Thanks.","commit_id":"s5"}]`),
				get("/pulls/4"+reviews, `[{"state":"CHANGES_REQUESTED","body":"Fixed since.","commit_id":"s0"}]`)},
			args: []string{"list"},
			stdout: []string{"CVE-2026-1100   PUBLISHED                      2026-10-23   bob",
				"CVE-2026-1101   RESERVED (in_review)",
				"CVE-2026-1102   RESERVED (changes requested)", "CVE-2026-1103   RESERVED (reserved)\n",
				"CVE-2026-1102: Add the CWE."},
		},
		{
			name: "list one state and year",
			exchanges: []cassette.Exchange{info,
				get("/git/trees/main?recursive=1", `{"tree":[{"path":"records/CVE-2026-1100.json"}]}`),
				get("/git/matching-refs/heads/cve/",
					`[{"ref":"refs/heads/cve/CVE-2025-0002"},{"ref":"refs/heads/cve/CVE-2026-1103"}]`),
				get("/pulls?per_page=100&state=all", `[]`)},
			args:   []string{"list", "--state", "reserved", "--year", "2026", "--json"},
			stdout: []string{"[\n  {\n    \"cve_id\": \"CVE-2026-1103\",", "\"state\": \"reserved\"\n    }\n  }\n]"},
		},
		{
			name: "list an empty repository",
			exchanges: []cassette.Exchange{info,
				{Method: "GET", Path: repo + "/git/trees/main?recursive=1", Status: 409,
					Response: `{"message":"Git Repository is empty."}`},
				{Method: "GET", Path: repo + "/git/matching-refs/heads/cve/", Status: 409,
					Response: `{"message":"Git Repository is empty."}`},
				get("/pulls?per_page=100&state=all", `[]`)},
			args:   []string{"list"},
			stdout: []string{"No CVE IDs. Reserve one with cvedex reserve."},
		},
		{
			name:   "list by time",
			args:   []string{"list", "--reserved-after", "2026-01-01"},
			code:   1,
			stderr: []string{"A GitHub repository cannot filter CVE IDs by time (NOT_SUPPORTED)"},
		},
		{
			name: "show a record in review",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/contents/records/CVE-2026-1101.json?ref=s4", contents(record, "blob"))},
			args:   []string{"show", "2026-1101"},
			stdout: []string{"CVE-2026-1101  IN_REVIEW", "Path traversal in widget", "acme widget"},
		},
		{
			name: "show a published record",
			exchanges: []cassette.Exchange{open("CVE-2026-1100", ""),
				get("/contents/records/CVE-2026-1100.json", contents(record, "blob"))},
			args:   []string{"show", "CVE-2026-1100"},
			stdout: []string{"CVE-2026-1100  PUBLISHED", "Path traversal in widget"},
		},
		{
			name:      "show an ID without a record",
			exchanges: []cassette.Exchange{open("CVE-2026-1103", ""), missing("/contents/records/CVE-2026-1103.json")},
			args:      []string{"show", "CVE-2026-1103"},
			code:      1,
			stderr:    []string{"The cve record for the cve id does not exist. (CVE_RECORD_DNE)"},
		},
		{
			name: "show a record that is not JSON",
			exchanges: []cassette.Exchange{open("CVE-2026-1100", ""),
				get("/contents/records/CVE-2026-1100.json", contents("<<<<<<< HEAD", "blob"))},
			args:   []string{"show", "CVE-2026-1100"},
			code:   1,
			stderr: []string{"records/CVE-2026-1100.json in the repository is not JSON (BAD_RECORD)"},
		},
		{
			name:   "show what is not a CVE ID",
			args:   []string{"show", "../../README"},
			code:   1,
			stderr: []string{`"../../README" is not a CVE ID (BAD_INPUT)`},
		},
		{
			name: "publish",
			exchanges: []cassette.Exchange{info,
				get("/git/ref/heads/cve/CVE-2026-1101", `{"ref":"refs/heads/cve/CVE-2026-1101","object":{"sha":"abc"}}`),
				missing("/contents/records/CVE-2026-1101.json?ref=cve/CVE-2026-1101"),
				{Method: "PUT", Path: repo + "/contents/records/CVE-2026-1101.json", Status: 201,
					Body:     `{"message":"CVE-2026-1101","branch":"cve/CVE-2026-1101","content":"` + committed(untitled) + `"}`,
					Response: `{"commit":{"sha":"s4"}}`},
				open("CVE-2026-1101", ""),
				{Method: "POST", Path: repo + "/pulls", Status: 201, Response: pull(4, "open", "CVE-2026-1101", "s4"),
					Body: `{"title":"CVE-2026-1101","head":"cve/CVE-2026-1101","base":"main",` +
						`"body":"Sent with ` + "`cvedex`. Read it with `cvedex review show CVE-2026-1101`" + `."}`}},
			args:   []string{"publish", "CVE-2026-1101", bare},
			stdout: []string{"Sent CVE-2026-1101 for review"},
		},
		{
			name: "update",
			exchanges: []cassette.Exchange{info, missing("/git/ref/heads/cve/CVE-2026-1100"),
				get("/git/ref/heads/main", `{"ref":"refs/heads/main","object":{"type":"commit","sha":"main-sha"}}`),
				branch("CVE-2026-1100", "main-sha", 201),
				get("/contents/records/CVE-2026-1100.json?ref=cve/CVE-2026-1100", contents(untitled, "blob")),
				{Method: "PUT", Path: repo + "/contents/records/CVE-2026-1100.json", Response: `{"commit":{"sha":"s9"}}`,
					Body: `{"message":"CVE-2026-1100: Path traversal in widget","branch":"cve/CVE-2026-1100","sha":"blob",` +
						`"content":"` + committed(record) + `"}`},
				open("CVE-2026-1100", pull(9, "open", "CVE-2026-1100", "s9"))},
			args:   []string{"update", "CVE-2026-1100", titled, "--json"},
			stdout: []string{`"state": "in_review"`, `"url": "https://github.com/acme/cves/pull/9"`},
		},
		{
			name: "review",
			exchanges: []cassette.Exchange{
				get("/pulls?per_page=100&state=open", "["+pull(5, "open", "CVE-2026-1102", "s5")+","+
					pull(4, "open", "CVE-2026-1101", "s4")+","+pull(6, "open", "CVE-2026-1103", "s6")+"]"),
				get("/contents/records/CVE-2026-1102.json?ref=s5", contents(record, "blob")),
				get("/pulls/5"+reviews, `[{"state":"CHANGES_REQUESTED","body":"Add the CWE.","commit_id":"s5"}]`),
				get("/contents/records/CVE-2026-1101.json?ref=s4", contents(record, "blob")),
				get("/pulls/4"+reviews, `[]`),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4")),
				missing("/contents/records/CVE-2026-1101.json"),
				missing("/contents/records/CVE-2026-1103.json?ref=s6")},
			args:   []string{"review"},
			stdout: []string{"CVE-2026-1101   publish   2     bob         2026-10-22   Path traversal in widget\n"},
		},
		{
			name: "review show an update",
			exchanges: []cassette.Exchange{get("/pulls?per_page=100&state=open", "["+pull(9, "open", "CVE-2026-1100", "s9")+"]"),
				get("/contents/records/CVE-2026-1100.json?ref=s9", contents(record, "blob")),
				get("/pulls/9"+reviews, `[]`),
				get("/pulls/9", pull(9, "open", "CVE-2026-1100", "s9")),
				get("/contents/records/CVE-2026-1100.json", contents(untitled, "old"))},
			args: []string{"review", "show", "CVE-2026-1100"},
			stdout: []string{"revision 2 from bob, asking to publish", "Changes from the published record",
				`+    "title": "Path traversal in widget"`, "cvedex review approve CVE-2026-1100 --revision 2"},
		},
		{
			name: "review approve",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4")), approved, merge,
				{Method: "DELETE", Path: repo + "/git/refs/heads/cve/CVE-2026-1101", Status: 204},
				get(published, `{"total_count":0,"workflow_runs":[]}`),
				get(published, `{"total_count":1,"workflow_runs":[{"id":8,"status":"completed","conclusion":"success"}]}`)},
			args:   approve,
			stdout: []string{"Approved CVE-2026-1101", "CVE-2026-1101  PUBLISHED"},
		},
		{
			name: "review approve your own record, on a repository that deletes merged branches",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4")),
				{Method: "POST", Path: repo + "/pulls/4/reviews", Status: 422,
					Response: `{"message":"Unprocessable Entity","errors":["Can not approve your own pull request"]}`},
				merge,
				{Method: "DELETE", Path: repo + "/git/refs/heads/cve/CVE-2026-1101", Status: 422,
					Response: `{"message":"Reference does not exist"}`},
				get(published, `{"workflow_runs":[{"id":8,"status":"completed","conclusion":"failure",`+
					`"html_url":"https://github.com/acme/cves/actions/runs/8"}]}`)},
			args:   approve,
			code:   1,
			stderr: []string{"The publish workflow failed: https://github.com/acme/cves/actions/runs/8"},
		},
		{
			name: "review approve a record that changed",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4"))},
			args:   []string{"review", "approve", "CVE-2026-1101", "--revision", "1"},
			code:   1,
			stderr: []string{"CVE-2026-1101 changed since revision 1 (STALE_REVISION)"},
		},
		{
			name: "review approve a record that changes meanwhile",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4")), approved,
				{Method: "PUT", Path: repo + "/pulls/4/merge", Status: 409,
					Response: `{"message":"Head branch was modified. Review and try the merge again."}`}},
			args:   approve,
			code:   1,
			stderr: []string{"CVE-2026-1101 changed since revision 2 (STALE_REVISION)"},
		},
		{
			name:      "review approve an ID that is not in review",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", "")},
			args:      approve,
			code:      1,
			stderr:    []string{"CVE-2026-1101 is not in review (NOT_IN_REVIEW)"},
		},
		{
			name: "review request-changes",
			exchanges: []cassette.Exchange{open("CVE-2026-1101", pull(4, "open", "CVE-2026-1101", "s4")),
				get("/pulls/4", pull(4, "open", "CVE-2026-1101", "s4")),
				{Method: "POST", Path: repo + "/pulls/4/reviews", Response: `{"id":81,"state":"CHANGES_REQUESTED"}`,
					Body: `{"event":"REQUEST_CHANGES","body":"Add the CWE.","commit_id":"s4"}`}},
			args:   []string{"review", "request-changes", "CVE-2026-1101", "Add the CWE.", "--revision", "2"},
			stdout: []string{"Sent CVE-2026-1101 back to its submitter."},
		},
		{
			name: "audit",
			exchanges: []cassette.Exchange{get("/actions/runs?actor=alice&created=>=2026-10-01&page=1&per_page=100",
				`{"workflow_runs":[`+
					`{"run_number":3,"name":"cvedex-publish","display_title":"CVE-2026-1101: Path traversal in widget (#4)",`+
					`"event":"push","status":"completed","conclusion":"success","created_at":"2026-10-22T11:05:00Z",`+
					`"actor":{"login":"alice"}},`+
					`{"run_number":2,"name":"cvedex-publish","display_title":"CVE-2026-1100","event":"push","status":"completed",`+
					`"conclusion":"failure","created_at":"2026-10-22T11:00:00Z","actor":{"login":"alice"}},`+
					`{"run_number":1,"name":"cvedex-reserve","display_title":"cvedex-reserve","event":"workflow_dispatch",`+
					`"status":"in_progress","conclusion":null,"created_at":"2026-10-22T10:00:00Z","actor":{"login":"alice"}}]}`)},
			args: []string{"audit", "--user", "alice", "--since", "2026-10-01"},
			stdout: []string{"2026-10-22 11:05:00   alice   push ",
				"cvedex-publish CVE-2026-1101: Path traversal in widget (#4)   200",
				"cvedex-publish CVE-2026-1100                                  500",
				"workflow_dispatch   cvedex-reserve cvedex-reserve                                 ?"},
		},
		{
			name: "audit an older page",
			exchanges: []cassette.Exchange{get("/actions/runs?page=2&per_page=100",
				`{"workflow_runs":[`+strings.Join(hundred, ",")+`]}`)},
			args:   []string{"audit", "--before", "2"},
			stdout: []string{"Older entries: cvedex audit --before 3"},
		},
		{
			name:   "proposals",
			args:   []string{"proposals"},
			code:   1,
			stderr: []string{"A GitHub repository has no proposals"},
		},
		{
			name:   "what a repository does not do",
			args:   []string{"org"},
			code:   1,
			stderr: []string{"A GitHub repository does not do this: it reserves IDs, and takes records for review"},
		},
		{
			name: "forbidden by GitHub",
			exchanges: []cassette.Exchange{{Method: "GET", Path: repo, Status: 403,
				Response: `{"message":"Resource not accessible by personal access token"}`}},
			args: []string{"list"},
			code: 1,
			stderr: []string{"GitHub: Resource not accessible by personal access token (GET /repos/acme/cves) (GITHUB_ERROR)",
				"Your user is not allowed to do this."},
		},
		{
			name:      "GitHub is down",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/user", Status: 503, Response: "<html>"}},
			args:      []string{"status"},
			code:      1,
			stderr:    []string{"GitHub: 503 Service Unavailable (GET /user) (GITHUB_ERROR)"},
		},
		{
			name:      "GitHub answers something else than JSON",
			exchanges: []cassette.Exchange{{Method: "GET", Path: "/user", Response: "<html>"}},
			args:      []string{"status"},
			code:      1,
			stderr:    []string{"reading GitHub's answer to GET /user: invalid character '<'", "(GITHUB_UNREACHABLE)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRepo(t, "", tt.exchanges, tt.args...)
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

func TestRepositoryLogin(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gh-token" {
			t.Errorf("%s %s: Authorization %q, want GitHub's token", r.Method, r.URL.Path, got)
		}
		if strings.Contains(fmt.Sprint(r.Header), "cve-services-key") {
			t.Errorf("%s %s: GitHub got the CVE Services key", r.Method, r.URL.Path)
		}
		if r.URL.Path == "/user" {
			_, _ = io.WriteString(w, `{"login":"alice"}`)
			return
		}
		_, _ = io.WriteString(w, `{"default_branch":"main","permissions":{"admin":false,"push":true,"pull":true}}`)
	}))
	t.Cleanup(api.Close)
	loggedOut(t, "")
	t.Setenv("GITHUB_API_URL", api.URL)
	t.Setenv("GH_TOKEN", "gh-token")
	t.Setenv("CVE_API_KEY", "cve-services-key")

	got := rerun("", "--url", repoURL, "login")
	if got.code != 0 || !strings.Contains(got.stdout, "Logged in to "+repoURL+" as alice (acme, write)") ||
		!strings.Contains(got.stdout, "GitHub keeps your login") {
		t.Fatalf("login: exit code %d, %s%s", got.code, got.stdout, got.stderr)
	}
	data, err := os.ReadFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "cvedex", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"user": "alice"`) || strings.Contains(string(data), "key") {
		t.Errorf("config: %s", data)
	}
	if _, err := keyring.Get("cvedex", "alice on "+repoURL); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("the keychain holds something for the repository: %v", err)
	}
	if got := rerun("", "status"); got.code != 0 || !strings.Contains(got.stdout, "alice write") {
		t.Errorf("status with the saved login: exit code %d, %s%s", got.code, got.stdout, got.stderr)
	}
	if got := rerun("", "logout"); got.code != 0 || !strings.Contains(got.stdout, "Logged out of "+repoURL+" as alice.") {
		t.Errorf("logout: exit code %d, %s%s", got.code, got.stdout, got.stderr)
	}
}

func TestRepositoryUnreachable(t *testing.T) {
	for _, tt := range []struct {
		name, api, token, want string
		args                   []string
	}{
		{name: "no GitHub login", args: []string{"--url", repoURL, "login"},
			want: "no GitHub login: run gh auth login, or set GH_TOKEN"},
		{name: "an unusable API URL", api: "http://[::1", token: "gh-token", args: []string{"status"},
			want: "missing ']' in host"},
		{name: "an API that is down", api: "http://127.0.0.1:1", token: "gh-token", args: []string{"status"},
			want: "127.0.0.1:1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			loggedOut(t, repoURL)
			t.Setenv("GITHUB_API_URL", tt.api)
			t.Setenv("GH_TOKEN", tt.token)
			t.Setenv("GITHUB_TOKEN", "")
			t.Setenv("CVE_API_ORG", "acme")
			t.Setenv("CVE_API_USER", "alice")
			// No gh to ask for a login.
			t.Setenv("PATH", t.TempDir())
			if got := rerun("", tt.args...); got.code != 1 || !strings.Contains(got.stderr, tt.want) {
				t.Errorf("exit code %d, stderr %q; want 1 and %q", got.code, got.stderr, tt.want)
			}
		})
	}
}

func TestLoginFormRepository(t *testing.T) {
	loggedOut(t, repoURL)
	t.Setenv("GH_TOKEN", "gh-token")
	t.Setenv("GITHUB_API_URL", cassette.Serve(t,
		cassette.Exchange{Method: "GET", Path: "/user", Response: `{"login":"alice"}`},
		cassette.Exchange{Method: "GET", Path: "/repos/acme/cves", Response: `{"permissions":{"admin":true,"push":true}}`},
	))
	term := startTerminal(t, "login")
	term.waitFor("> Another server")
	term.answer("\r", "Server URL")
	term.send("\r")
	term.waitFor("Logged in to " + repoURL + " as alice (acme, admin)")
	term.exits(0)
}
