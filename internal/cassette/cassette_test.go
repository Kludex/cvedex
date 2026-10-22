package cassette_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Kludex/cvedex/internal/cassette"
)

// recorder is a testing.TB that collects failures instead of failing the test.
type recorder struct {
	testing.TB
	mu       sync.Mutex
	failures []string
	cleanups []func()
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatal(args ...any) {
	r.Errorf("%s", fmt.Sprint(args...))
	runtime.Goexit()
}

func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }

// finish runs the cleanups, as the end of a test would, and returns the failures.
func (r *recorder) finish() string {
	for _, f := range r.cleanups {
		f()
	}
	return strings.Join(r.failures, "\n")
}

func TestServeReportsMismatches(t *testing.T) {
	r := &recorder{}
	url := cassette.Serve(r,
		cassette.Exchange{Method: "GET", Path: "/api/a"},
		cassette.Exchange{Method: "POST", Path: "/api/b", Body: `{"x":1}`, User: "alice"},
		cassette.Exchange{Method: "POST", Path: "/api/c", Body: "not json"},
		cassette.Exchange{Method: "GET", Path: "/api/never"},
	)
	send := func(method, path, body string) {
		req, err := http.NewRequest(method, url+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("CVE-API-USER", "bob")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	send("GET", "/api/wrong?q=1", "")
	send("POST", "/api/b", `{"x":2}`)
	send("POST", "/api/c", "other")
	failures := r.finish()
	for _, want := range []string{
		"request 1: got GET /api/wrong?q=1, want GET /api/a",
		`request 2 body: got {"x":2}, want {"x":1}`,
		`request 2 CVE-API-USER: got "bob", want "alice"`,
		"request 3 body: got other, want not json",
		"1 of 4 expected requests were never made",
	} {
		if !strings.Contains(failures, want) {
			t.Errorf("missing %q in:\n%s", want, failures)
		}
	}
}

func TestServeReportsUnexpectedRequests(t *testing.T) {
	r := &recorder{}
	resp, err := http.Get(cassette.Serve(r) + "/api/extra")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	failures := r.finish()
	if resp.StatusCode != http.StatusTeapot || !strings.Contains(failures, "unexpected request GET /api/extra") {
		t.Errorf("status %d, failures: %s", resp.StatusCode, failures)
	}
}

func TestLoadFailsOnMissingOrBrokenCassettes(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	recorded := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "recorded")
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(recorded, strings.TrimSuffix(broken, ".json"))
	if err != nil {
		t.Skip("the temporary directory is on another volume")
	}
	cases := map[string]string{"does-not-exist": "does-not-exist.json", relative: "cannot unmarshal array"}
	for name, want := range cases {
		r := &recorder{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			cassette.Load(r, name)
		}()
		<-done
		if failures := r.finish(); !strings.Contains(failures, want) {
			t.Errorf("Load(%q): got %q, want it to contain %q", name, failures, want)
		}
	}
}
