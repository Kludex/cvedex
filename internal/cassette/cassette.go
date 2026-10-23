// Package cassette replays CVE Services traffic recorded by scripts/record-fixtures.mjs, for tests.
package cassette

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

// Exchange is one request a test expects and the response to give it.
type Exchange struct {
	Method string
	// Path includes the query string.
	Path string
	// Body, when set, must equal the request body, as JSON when both are.
	Body string
	// User, when set, must equal the CVE-API-USER header.
	User     string
	Status   int
	Header   map[string]string
	Response string
}

// Load reads testdata/recorded/<name>.json.
func Load(t testing.TB, name string) Exchange {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "recorded", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Request struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			Body   string `json:"body"`
		} `json:"request"`
		Response struct {
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		} `json:"response"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return Exchange{
		Method:   c.Request.Method,
		Path:     c.Request.Path,
		Body:     c.Request.Body,
		Status:   c.Response.Status,
		Header:   c.Response.Headers,
		Response: c.Response.Body,
	}
}

// Serve answers exchanges in order and returns the server's URL. The test fails on a request
// that does not match the next exchange, and on exchanges left unanswered at the end.
func Serve(t testing.TB, exchanges ...Exchange) string {
	t.Helper()
	var mu sync.Mutex
	next := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if next == len(exchanges) {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusTeapot)
			return
		}
		e := exchanges[next]
		next++
		want, _ := url.PathUnescape(e.Path)
		if got, _ := url.PathUnescape(r.URL.EscapedPath() + query(r.URL)); r.Method != e.Method || got != want {
			t.Errorf("request %d: got %s %s, want %s %s", next, r.Method, r.URL.RequestURI(), e.Method, e.Path)
		}
		if e.Body != "" && !sameJSON(body, []byte(e.Body)) {
			t.Errorf("request %d body: got %s, want %s", next, body, e.Body)
		}
		if e.User != "" && r.Header.Get("CVE-API-USER") != e.User {
			t.Errorf("request %d CVE-API-USER: got %q, want %q", next, r.Header.Get("CVE-API-USER"), e.User)
		}
		w.Header().Set("Content-Type", "application/json")
		for name, value := range e.Header {
			w.Header().Set(name, value)
		}
		w.WriteHeader(max(e.Status, http.StatusOK))
		_, _ = io.WriteString(w, e.Response)
	}))
	t.Cleanup(func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		if next < len(exchanges) && !t.Skipped() {
			t.Errorf("%d of %d expected requests were never made", len(exchanges)-next, len(exchanges))
		}
	})
	return server.URL
}

func query(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return string(a) == string(b)
	}
	return reflect.DeepEqual(x, y)
}
