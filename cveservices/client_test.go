package cveservices_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kludex/cvedex/cveservices"
)

func TestNewDefaultsToProduction(t *testing.T) {
	if got := cveservices.New(cveservices.Credentials{}).Credentials.URL; got != cveservices.ProductionURL {
		t.Errorf("URL: got %q, want %q", got, cveservices.ProductionURL)
	}
}

func TestDoErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) {
		t.Error("the client followed a redirect, taking the API key with it")
	})
	mux.HandleFunc("/message", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":"Something broke"}`)
	})
	mux.HandleFunc("/proposal", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"proposal_id":"p1"}`)
	})
	mux.HandleFunc("/cut", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, `{"cut":`)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	closed := httptest.NewServer(mux)
	closed.Close()

	tests := []struct {
		name   string
		url    string
		method string
		path   string
		body   any
		want   string
	}{
		{name: "redirect", url: server.URL, method: "GET", path: "/redirect", want: "HTTP 302 Found"},
		{name: "message without a code", url: server.URL, method: "GET", path: "/message", want: "Something broke"},
		{name: "proposal", url: server.URL, method: "POST", path: "/proposal", want: "waiting for approval as proposal p1"},
		{name: "body cut short", url: server.URL, method: "GET", path: "/cut", want: "unexpected EOF"},
		{name: "server down", url: closed.URL, method: "GET", path: "/", want: "connect"},
		{name: "invalid method", url: server.URL, method: "NOT A METHOD", path: "/", want: "invalid method"},
		{name: "invalid body", url: server.URL, method: "POST", path: "/", body: json.RawMessage("{"),
			want: "unexpected end"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cveservices.New(cveservices.Credentials{URL: tt.url})
			err := client.Do(context.Background(), tt.method, tt.path, nil, tt.body, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestRetryRateLimited(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter string
		limited    int
		cancel     bool
		want       string
	}{
		{name: "recovers", retryAfter: "0", limited: 2},
		{name: "default wait", limited: 1},
		{name: "gives up", retryAfter: "0", limited: 10, want: "HTTP 429 Too Many Requests"},
		{name: "cancelled", retryAfter: "30", limited: 1, cancel: true, want: "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				if calls > tt.limited {
					_, _ = io.WriteString(w, `{}`)
					return
				}
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				if tt.cancel {
					time.AfterFunc(100*time.Millisecond, cancel)
				}
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			t.Cleanup(server.Close)
			err := cveservices.New(cveservices.Credentials{URL: server.URL}).Do(ctx, "GET", "/", nil, nil, nil)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Errorf("got %v, want %q", err, tt.want)
			}
		})
	}
}
