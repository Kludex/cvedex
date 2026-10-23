package record_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/Kludex/cvedex/internal/cassette"
	"github.com/Kludex/cvedex/internal/record"
)

const advisoryURL = "https://github.com/Kludex/python-multipart/security/advisories/GHSA-59g5-xgcq-4qw3"

// fromAdvisory serves the recorded advisory with fields replaced by patch, and returns the
// container built from it.
func fromAdvisory(t *testing.T, patch map[string]any) map[string]json.RawMessage {
	t.Helper()
	exchange := cassette.Load(t, "advisory")
	var body map[string]any
	if err := json.Unmarshal([]byte(exchange.Response), &body); err != nil {
		t.Fatal(err)
	}
	maps.Copy(body, patch)
	patched, _ := json.Marshal(body)
	exchange.Response = string(patched)
	t.Setenv("GITHUB_API_URL", cassette.Serve(t, exchange))
	cna, err := record.FromAdvisory(context.Background(), advisoryURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Check(cna); err != nil {
		t.Errorf("the container is invalid: %v", err.(*record.InvalidError).Problems)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(cna, &fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func compact(t *testing.T, data json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

func TestFromAdvisoryVersions(t *testing.T) {
	pip := `{"ecosystem":"pip","name":"python-multipart"}`
	tests := []struct {
		pkg, rng string
		want     string
	}{
		{pip, "<0.0.18", `{"status":"affected","version":"0","lessThan":"0.0.18","versionType":"python"}`},
		{pip, ">= 1.0, < 2.0", `{"status":"affected","version":"1.0","lessThan":"2.0","versionType":"python"}`},
		{pip, ">= 1.0, <= 2.0", `{"status":"affected","version":"1.0","lessThanOrEqual":"2.0","versionType":"python"}`},
		{pip, "= 1.0", `{"status":"affected","version":"1.0"}`},
		{pip, ">= 1.0", `{"status":"affected","version":">= 1.0"}`},
		{pip, "> 1.0, < 2.0", `{"status":"affected","version":"> 1.0, < 2.0"}`},
		{pip, "= 1.0, < 2.0", `{"status":"affected","version":"= 1.0, < 2.0"}`},
		{`{"ecosystem":"maven","name":"org.acme:widget"}`, "< 2.0",
			`{"status":"affected","version":"0","lessThan":"2.0","versionType":"maven"}`},
		{`{"ecosystem":"erlang","name":"widget"}`, "< 2.0",
			`{"status":"affected","version":"0","lessThan":"2.0","versionType":"custom"}`},
	}
	for _, tt := range tests {
		t.Run(tt.pkg+" "+tt.rng, func(t *testing.T) {
			var pkg any
			_ = json.Unmarshal([]byte(tt.pkg), &pkg)
			vulns := []any{map[string]any{"package": pkg, "vulnerable_version_range": tt.rng}}
			var affected []map[string]json.RawMessage
			_ = json.Unmarshal(fromAdvisory(t, map[string]any{"vulnerabilities": vulns})["affected"], &affected)
			if got := compact(t, affected[0]["versions"]); got != compact(t, json.RawMessage("["+tt.want+"]")) {
				t.Errorf("versions %s, want [%s]", got, tt.want)
			}
		})
	}
}

func TestFromAdvisoryAffected(t *testing.T) {
	vulns := []any{
		map[string]any{"package": map[string]any{"ecosystem": "erlang", "name": "widget"}, "vulnerable_version_range": "< 2"},
		map[string]any{"package": nil, "vulnerable_version_range": "< 2"},
	}
	got := compact(t, fromAdvisory(t, map[string]any{"vulnerabilities": vulns})["affected"])
	want := `[{"defaultStatus":"unaffected","product":"widget","repo":"https://github.com/Kludex/python-multipart",` +
		`"vendor":"Kludex","versions":[{"lessThan":"2","status":"affected","version":"0","versionType":"custom"}]},` +
		`{"defaultStatus":"unaffected","product":"python-multipart","repo":"https://github.com/Kludex/python-multipart",` +
		`"vendor":"Kludex","versions":[{"lessThan":"2","status":"affected","version":"0","versionType":"custom"}]}]`
	if got != want {
		t.Errorf("affected %s", got)
	}
}

func TestFromAdvisoryTitle(t *testing.T) {
	tests := []struct{ summary, want string }{
		{"Denial of service via a boundary", "python-multipart has denial of service via a boundary"},
		{"DoS via a boundary", "python-multipart has DoS via a boundary"},
		{"XSS in the form", "python-multipart has XSS in the form"},
		{"Élévation de privilèges", "python-multipart has élévation de privilèges"},
		{"Python-Multipart vulnerable to DoS", "Python-Multipart vulnerable to DoS"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.summary, func(t *testing.T) {
			var got string
			if title, ok := fromAdvisory(t, map[string]any{"summary": tt.summary})["title"]; ok {
				_ = json.Unmarshal(title, &got)
			}
			if got != tt.want {
				t.Errorf("title %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFromAdvisoryMetrics(t *testing.T) {
	v3 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
	v4 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
	cvss := func(vector string, score float64) map[string]any {
		return map[string]any{"vector_string": vector, "score": score}
	}
	tests := []struct {
		name   string
		v3, v4 map[string]any
		want   string
	}{
		{"none", cvss("", 0), cvss("", 0), ``},
		{"3.0 critical", cvss("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), cvss("", 0),
			`[{"cvssV3_0":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":` +
				`"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","version":"3.0"}}]`},
		{"3.1 and 4.0", cvss(v3, 5.3), cvss(v4, 2), `[{"cvssV3_1":{"baseScore":5.3,"baseSeverity":"MEDIUM",` +
			`"vectorString":"` + v3 + `","version":"3.1"}},{"cvssV4_0":{"baseScore":2,"baseSeverity":"LOW",` +
			`"vectorString":"` + v4 + `","version":"4.0"}}]`},
		{"high", cvss(v3, 7.5), cvss("CVSS:2.0/AV:N", 5), `[{"cvssV3_1":{"baseScore":7.5,"baseSeverity":"HIGH",` +
			`"vectorString":"` + v3 + `","version":"3.1"}}]`},
		{"no score", cvss(v3, 0), cvss("", 0), `[{"cvssV3_1":{"baseScore":0,"baseSeverity":"NONE",` +
			`"vectorString":"` + v3 + `","version":"3.1"}}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := fromAdvisory(t, map[string]any{"cvss_severities": map[string]any{"cvss_v3": tt.v3, "cvss_v4": tt.v4}})
			got := ""
			if metrics, ok := fields["metrics"]; ok {
				got = compact(t, metrics)
			}
			if got != tt.want {
				t.Errorf("metrics %s\nwant    %s", got, tt.want)
			}
		})
	}
}

func TestFromAdvisoryText(t *testing.T) {
	fields := fromAdvisory(t, map[string]any{
		"cwes": []any{},
		"description": "See https://example.com/a. Also [this](https://example.com/b), https://example.com/a again and " +
			advisoryURL + ".",
	})
	if _, ok := fields["problemTypes"]; ok {
		t.Errorf("problemTypes without CWEs: %s", fields["problemTypes"])
	}
	want := `[{"tags":["vendor-advisory"],"url":"` + advisoryURL + `"},{"url":"https://example.com/a"},` +
		`{"url":"https://example.com/b"}]`
	if got := compact(t, fields["references"]); got != want {
		t.Errorf("references %s", got)
	}
}

func TestFromAdvisoryFailures(t *testing.T) {
	tests := []struct {
		name, url, api, token string
		exchanges             []cassette.Exchange
		want                  string
	}{
		{name: "not an advisory URL", url: "https://github.com/advisories/GHSA-59g5-xgcq-4qw3",
			want: "is not a GitHub repository advisory, such as https://github.com/OWNER/REPO/security/advisories/GHSA-"},
		{name: "a missing advisory", url: "https://github.com/Kludex/starlette/security/advisories/GHSA-xxxx-xxxx-xxxx",
			exchanges: []cassette.Exchange{cassette.Load(t, "advisory-dne")},
			want:      "GitHub found no published advisory GHSA-xxxx-xxxx-xxxx in Kludex/starlette. For a draft, set GH_TOKEN"},
		{name: "a missing advisory with a token", token: "token",
			url:       "https://github.com/Kludex/starlette/security/advisories/GHSA-xxxx-xxxx-xxxx",
			exchanges: []cassette.Exchange{cassette.Load(t, "advisory-dne")},
			want:      "GitHub answered 404 Not Found: Not Found"},
		{name: "not JSON", url: advisoryURL,
			exchanges: []cassette.Exchange{{Method: "GET", Path: cassette.Load(t, "advisory").Path, Response: "<html>"}},
			want:      "reading the advisory from GitHub: invalid character '<'"},
		{name: "an unusable API URL", url: advisoryURL, api: "http://[::1", want: "missing ']' in host"},
		{name: "an API that is down", url: advisoryURL, api: "http://127.0.0.1:1", want: "127.0.0.1:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := cassette.Serve(t, tt.exchanges...)
			if tt.api != "" {
				api = tt.api
			}
			t.Setenv("GITHUB_API_URL", api)
			t.Setenv("GH_TOKEN", "")
			t.Setenv("GITHUB_TOKEN", tt.token)
			_, err := record.FromAdvisory(context.Background(), tt.url)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	var published struct {
		CNA map[string]any `json:"cnaContainer"`
	}
	if err := json.Unmarshal([]byte(cassette.Load(t, "publish").Body), &published); err != nil {
		t.Fatal(err)
	}
	valid, _ := json.Marshal(published.CNA)
	delete(published.CNA, "providerMetadata")
	withoutMetadata, _ := json.Marshal(published.CNA)
	tests := []struct {
		name string
		cna  string
		want []string
	}{
		{name: "valid", cna: string(valid)},
		{name: "valid without providerMetadata", cna: string(withoutMetadata)},
		{name: "not JSON", cna: "nope", want: []string{"- it is not a JSON object"}},
		{name: "an array", cna: "[]", want: []string{"- it is not a JSON object"}},
		{name: "empty", cna: "{}", want: []string{"- missing properties 'descriptions', 'affected', 'references'"}},
		{
			name: "nested problems",
			cna: `{"descriptions":[{"lang":"en","value":"x"}],"references":[{"url":"https://acme.org"}],"bogus":1,` +
				`"affected":[{"vendor":"acme","product":"widget",` +
				`"versions":[{"version":"0","lessThan":"2","status":"affected"}]}]}`,
			want: []string{
				"- /affected/0/versions/0: 'oneOf' failed, none matched",
				"  - maxProperties: got 3, want 2",
				"  - missing property 'versionType'",
				"  - missing properties 'versionType', 'lessThanOrEqual'",
				"- additional properties 'bogus' not allowed",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := record.Check([]byte(tt.cna))
			var invalid *record.InvalidError
			switch {
			case tt.want == nil && err != nil:
				t.Errorf("unexpected %v: %v", err, err.(*record.InvalidError).Problems)
			case tt.want != nil && !errors.As(err, &invalid):
				t.Errorf("error %v, want problems", err)
			case tt.want != nil && strings.Join(invalid.Problems, "\n") != strings.Join(tt.want, "\n"):
				t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(invalid.Problems, "\n"), strings.Join(tt.want, "\n"))
			case tt.want != nil && invalid.Error() != "not a valid CNA container":
				t.Errorf("message %q", invalid.Error())
			}
		})
	}
}
