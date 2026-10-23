package record

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
)

// AdvisoryHint is the start of a GitHub repository advisory URL, for help and error messages.
const AdvisoryHint = "https://github.com/OWNER/REPO/security/advisories/GHSA-..."

var advisoryURL = regexp.MustCompile(
	`^https://github\.com/([^/]+)/([^/]+)/security/advisories/(GHSA(?:-[0-9a-z]{4}){3})/?$`)

// FromAdvisory fetches a GitHub repository advisory and builds a CNA container from it. It
// authenticates with GH_TOKEN or GITHUB_TOKEN when set, which drafts need, and reads the API at
// GITHUB_API_URL, else https://api.github.com.
func FromAdvisory(ctx context.Context, url string) (json.RawMessage, error) {
	parts := advisoryURL.FindStringSubmatch(url)
	if parts == nil {
		return nil, fmt.Errorf("%s is not a GitHub repository advisory, such as %s", url, AdvisoryHint)
	}
	owner, repo, ghsa := parts[1], parts[2], parts[3]
	api := cmp.Or(os.Getenv("GITHUB_API_URL"), "https://api.github.com")
	token := cmp.Or(os.Getenv("GH_TOKEN"), os.Getenv("GITHUB_TOKEN"))
	path := fmt.Sprintf("%s/repos/%s/%s/security-advisories/%s", strings.TrimSuffix(api, "/"), owner, repo, ghsa)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	var a advisory
	switch {
	case res.StatusCode == http.StatusNotFound && token == "":
		return nil, fmt.Errorf("GitHub found no published advisory %s in %s/%s. For a draft, set GH_TOKEN, "+
			"for example GH_TOKEN=$(gh auth token)", ghsa, owner, repo)
	case res.StatusCode != http.StatusOK:
		var body struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(res.Body).Decode(&body)
		return nil, fmt.Errorf("GitHub answered %s: %s", res.Status, body.Message)
	}
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return nil, fmt.Errorf("reading the advisory from GitHub: %w", err)
	}
	return json.MarshalIndent(a.container(owner, repo), "", "  ")
}

type advisory struct {
	GHSAID          string `json:"ghsa_id"`
	HTMLURL         string `json:"html_url"`
	Summary         string `json:"summary"`
	Description     string `json:"description"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
	CVSS struct {
		V3 cvss `json:"cvss_v3"`
		V4 cvss `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CWEs []struct {
		ID   string `json:"cwe_id"`
		Name string `json:"name"`
	} `json:"cwes"`
	Credits []struct {
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		Type string `json:"type"`
	} `json:"credits_detailed"`
}

type cvss struct {
	Vector string  `json:"vector_string"`
	Score  float64 `json:"score"`
}

type (
	container struct {
		Title        string        `json:"title,omitempty"`
		Descriptions []text        `json:"descriptions"`
		Affected     []affected    `json:"affected"`
		ProblemTypes []problemType `json:"problemTypes,omitempty"`
		Metrics      []metric      `json:"metrics,omitempty"`
		References   []reference   `json:"references"`
		Credits      []credit      `json:"credits,omitempty"`
		Source       source        `json:"source"`
	}
	text struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	affected struct {
		Vendor        string    `json:"vendor"`
		Product       string    `json:"product"`
		CollectionURL string    `json:"collectionURL,omitempty"`
		PackageName   string    `json:"packageName,omitempty"`
		Repo          string    `json:"repo"`
		DefaultStatus string    `json:"defaultStatus"`
		Versions      []version `json:"versions"`
	}
	version struct {
		Version         string `json:"version"`
		LessThan        string `json:"lessThan,omitempty"`
		LessThanOrEqual string `json:"lessThanOrEqual,omitempty"`
		Status          string `json:"status"`
		VersionType     string `json:"versionType,omitempty"`
	}
	problemType struct {
		Descriptions []cwe `json:"descriptions"`
	}
	cwe struct {
		Lang        string `json:"lang"`
		Type        string `json:"type"`
		CWEID       string `json:"cweId"`
		Description string `json:"description"`
	}
	metric map[string]score
	score  struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	}
	reference struct {
		URL  string   `json:"url"`
		Tags []string `json:"tags,omitempty"`
	}
	credit struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
		Type  string `json:"type"`
	}
	source struct {
		Advisory  string `json:"advisory"`
		Discovery string `json:"discovery"`
	}
)

// registries maps a GitHub ecosystem to its CVE versionType and package registry. Others get
// "custom" and no registry.
var registries = map[string][2]string{
	"pip":      {"python", "https://pypi.org"},
	"npm":      {"semver", "https://www.npmjs.com"},
	"rust":     {"semver", "https://crates.io"},
	"go":       {"semver", "https://pkg.go.dev"},
	"maven":    {"maven", "https://repo.maven.apache.org/maven2"},
	"rubygems": {"custom", "https://rubygems.org"},
	"nuget":    {"custom", "https://www.nuget.org"},
	"composer": {"custom", "https://packagist.org"},
}

var link = regexp.MustCompile("https?://[^\\s<>()\\[\\]\"'`]+")

func (a advisory) container(owner, repo string) container {
	c := container{
		Title:        a.Summary,
		Descriptions: []text{{Lang: "en", Value: a.Description}},
		References:   []reference{{URL: a.HTMLURL, Tags: []string{"vendor-advisory"}}},
		Source:       source{Advisory: a.GHSAID, Discovery: "UNKNOWN"},
	}
	for _, v := range a.Vulnerabilities {
		registry, known := registries[v.Package.Ecosystem]
		entry := affected{
			Vendor:        owner,
			Product:       cmp.Or(v.Package.Name, repo),
			Repo:          "https://github.com/" + owner + "/" + repo,
			DefaultStatus: "unaffected",
			Versions:      []version{versionRange(v.Range, cmp.Or(registry[0], "custom"))},
		}
		if known {
			entry.CollectionURL, entry.PackageName = registry[1], v.Package.Name
		}
		c.Affected = append(c.Affected, entry)
	}
	if len(a.CWEs) > 0 {
		var cwes []cwe
		for _, w := range a.CWEs {
			cwes = append(cwes, cwe{Lang: "en", Type: "CWE", CWEID: w.ID, Description: w.ID + ": " + w.Name})
		}
		c.ProblemTypes = []problemType{{Descriptions: cwes}}
	}
	for _, s := range []cvss{a.CVSS.V3, a.CVSS.V4} {
		if key, ver, ok := cvssVersion(s.Vector); ok {
			c.Metrics = append(c.Metrics, metric{key: {ver, s.Vector, s.Score, severity(s.Score)}})
		}
	}
	for _, url := range link.FindAllString(a.Description, -1) {
		url = strings.TrimRight(url, ".,;:!?")
		if !slices.ContainsFunc(c.References, func(r reference) bool { return r.URL == url }) {
			c.References = append(c.References, reference{URL: url})
		}
	}
	for _, cr := range a.Credits {
		c.Credits = append(c.Credits, credit{Lang: "en", Value: cr.User.Login, Type: strings.ReplaceAll(cr.Type, "_", " ")})
	}
	return c
}

var bound = regexp.MustCompile(`^(>=|<=|<|=)\s*(\S+)$`)

// versionRange turns GitHub's range, such as ">= 1.0, < 1.4.2", into a CVE version entry. A
// range it cannot express is kept as GitHub wrote it, as GitHub's own CNA does.
func versionRange(text, versionType string) version {
	v := version{Version: "0", Status: "affected", VersionType: versionType}
	for part := range strings.SplitSeq(text, ",") {
		m := bound.FindStringSubmatch(strings.TrimSpace(part))
		switch {
		case m == nil:
			return version{Version: text, Status: "affected"}
		case m[1] == ">=":
			v.Version = m[2]
		case m[1] == "<":
			v.LessThan = m[2]
		case m[1] == "<=":
			v.LessThanOrEqual = m[2]
		case m[1] == "=" && !strings.Contains(text, ","):
			return version{Version: m[2], Status: "affected"}
		default:
			return version{Version: text, Status: "affected"}
		}
	}
	if v.LessThan == "" && v.LessThanOrEqual == "" {
		return version{Version: text, Status: "affected"}
	}
	return v
}

func cvssVersion(vector string) (key, ver string, ok bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return "cvssV3_0", "3.0", true
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		return "cvssV3_1", "3.1", true
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return "cvssV4_0", "4.0", true
	}
	return "", "", false
}

func severity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "NONE"
}
