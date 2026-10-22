package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/cassette"
	"github.com/Kludex/cvedex/internal/mcpserver"
)

func connect(t *testing.T, exchanges ...cassette.Exchange) *mcp.ClientSession {
	t.Helper()
	return connectTo(t, cassette.Serve(t, exchanges...))
}

func connectTo(t *testing.T, url string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	client := cveservices.New(cveservices.Credentials{URL: url, Org: "acme", User: "alice@acme.test", Key: "key"})
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := mcpserver.New(client, "test").Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestTools(t *testing.T) {
	tools, err := connect(t).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if tool.Annotations == nil {
			t.Errorf("%s has no annotations", tool.Name)
		}
	}
	slices.Sort(names)
	if want := []string{"list_cves", "publish_cve", "reserve_ids", "show_cve", "update_cve"}; !slices.Equal(
		names,
		want,
	) {
		t.Errorf("tools %v, want %v", names, want)
	}
}

func TestCallTool(t *testing.T) {
	publish := cassette.Load(t, "publish")
	var sent struct {
		CNA map[string]any `json:"cnaContainer"`
	}
	if err := json.Unmarshal([]byte(publish.Body), &sent); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		exchange cassette.Exchange
		tool     string
		args     map[string]any
		isError  bool
		want     string
	}{
		{
			name:     "list",
			exchange: cassette.Load(t, "cve-id-list"),
			tool:     "list_cves",
			args:     map[string]any{},
			want:     `"cve_id":"CVE-2026-1100"`,
		},
		{
			name:     "show",
			exchange: cassette.Load(t, "cve-2025-0001"),
			tool:     "show_cve",
			args:     map[string]any{"cve_id": "CVE-2025-0001"},
			want:     `"cveId":"CVE-2025-0001"`,
		},
		{name: "show missing", exchange: cassette.Load(t, "cve-record-dne"), tool: "show_cve",
			args: map[string]any{"cve_id": "CVE-2021-44228"}, isError: true, want: `"error":"CVE_RECORD_DNE"`},
		{
			name:     "reserve",
			exchange: cassette.Load(t, "reserve"),
			tool:     "reserve_ids",
			args:     map[string]any{"year": 2026},
			want:     `"cve_id":"CVE-2026-1100"`,
		},
		{name: "reserve as an agent", tool: "reserve_ids", args: map[string]any{"year": 2026},
			exchange: cassette.Exchange{
				Method:   "POST",
				Path:     "/api/cve-id?amount=1&cve_year=2026&short_name=acme",
				Status:   202,
				Response: `{"proposal_id":"p1"}`,
			},
			want: `{"proposal_id":"p1","status":"pending_approval"}`},
		{
			name:     "publish",
			exchange: publish,
			tool:     "publish_cve",
			args:     map[string]any{"cve_id": "CVE-2026-1100", "cna_container": sent.CNA},
			want:     `"state":"PUBLISHED"`,
		},
		{name: "update", tool: "update_cve", args: map[string]any{"cve_id": "CVE-2026-1100", "cna_container": sent.CNA},
			exchange: cassette.Exchange{
				Method: "PUT",
				Path:   "/api/cve/CVE-2026-1100/cna",
				Body:   publish.Body,
				Status: 500,
			},
			isError: true, want: "HTTP 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := connect(
				t,
				tt.exchange,
			).CallTool(context.Background(), &mcp.CallToolParams{Name: tt.tool, Arguments: tt.args})
			if err != nil {
				t.Fatal(err)
			}
			text := res.Content[0].(*mcp.TextContent).Text
			if res.IsError != tt.isError || !strings.Contains(text, tt.want) {
				t.Errorf("isError %v, text %s; want %v and %s", res.IsError, text, tt.isError, tt.want)
			}
		})
	}
}

func TestServerDown(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	res, err := connectTo(t, server.URL).CallTool(context.Background(), &mcp.CallToolParams{Name: "list_cves"})
	if err != nil {
		t.Fatal(err)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !res.IsError || !strings.Contains(text, "connect") {
		t.Errorf("isError %v, text %s", res.IsError, text)
	}
}
