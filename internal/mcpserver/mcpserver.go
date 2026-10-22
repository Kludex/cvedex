// Package mcpserver exposes CVE Services to AI agents as MCP tools. Against cvedexd with an agent
// token, writes come back as pending proposals that the submitter approves.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Kludex/cvedex/cveservices"
)

// New returns an MCP server whose tools call CVE Services with client.
func New(client *cveservices.Client, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "cvedex", Version: version}, nil)
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	destructive := &mcp.ToolAnnotations{DestructiveHint: new(true)}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_cves",
		Description: "List the CNA's CVE IDs with their state, optionally only those in one state.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
		State string `json:"state,omitempty" jsonschema:"RESERVED, PUBLISHED or REJECTED"`
	}) (*mcp.CallToolResult, any, error) {
		return result(client.ListIDs(ctx, in.State))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "show_cve",
		Description: "Show a CVE record as CVE JSON 5.",
		Annotations: readOnly,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
		CVEID string `json:"cve_id" jsonschema:"the CVE ID, such as CVE-2026-1234"`
	}) (*mcp.CallToolResult, any, error) {
		return result(client.Record(ctx, in.CVEID))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "reserve_ids",
		Description: "Reserve CVE IDs for the CNA. Each reserved ID counts against the CNA's quota.",
		Annotations: destructive,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct {
		Year       int  `json:"year" jsonschema:"year of the IDs"`
		Count      int  `json:"count,omitempty" jsonschema:"how many IDs, 1 by default"`
		Sequential bool `json:"sequential,omitempty" jsonschema:"ask for consecutive IDs"`
	}) (*mcp.CallToolResult, any, error) {
		return result(
			client.Reserve(ctx, cveservices.ReserveOptions{Year: in.Year, Count: in.Count, Sequential: in.Sequential}),
		)
	})

	type recordInput struct {
		CVEID        string         `json:"cve_id"        jsonschema:"the CVE ID, such as CVE-2026-1234"`
		CNAContainer map[string]any `json:"cna_container" jsonschema:"the CNA container of a CVE JSON 5 record"`
	}
	type sender func(context.Context, string, json.RawMessage) (json.RawMessage, error)
	write := func(send sender) mcp.ToolHandlerFor[recordInput, any] {
		return func(ctx context.Context, _ *mcp.CallToolRequest, in recordInput) (*mcp.CallToolResult, any, error) {
			cna, _ := json.Marshal(in.CNAContainer) // decoded from JSON, so it cannot fail
			return result(send(ctx, in.CVEID, cna))
		}
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "publish_cve",
		Description: "Publish the record of a reserved CVE ID. It becomes public.",
		Annotations: destructive,
	}, write(client.Publish))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "update_cve",
		Description: "Replace the CNA container of a published CVE record.",
		Annotations: destructive,
	}, write(client.Update))
	return s
}

// result turns a client call into a tool result: the value as JSON, an upstream error body
// verbatim, or a pending proposal.
func result[T any](v T, err error) (*mcp.CallToolResult, any, error) {
	var apiErr *cveservices.Error
	var pending *cveservices.PendingApproval
	var data []byte
	switch {
	case errors.As(err, &pending):
		data, err = json.Marshal(map[string]string{"status": "pending_approval", "proposal_id": pending.ProposalID})
	case errors.As(err, &apiErr):
		text := string(apiErr.Body)
		if text == "" {
			text = apiErr.Error()
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}, IsError: true}, nil, nil
	case err == nil:
		data, err = json.Marshal(v)
	}
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
}
