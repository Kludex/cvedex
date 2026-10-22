package cli

import (
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/internal/mcpserver"
	"github.com/Kludex/cvedex/internal/tui"
)

func (a *app) tuiCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Short:   "Browse CVE IDs, records and, on cvedexd, reviews in a full-screen interface",
		GroupID: groupTools,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return tui.Run(cmd.Context(), a.client)
		},
	}
}

func (a *app) mcpCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve CVE Services to AI agents over MCP on stdio",
		Long: "Serves CVE Services to AI agents as MCP tools over stdin and stdout. Give agents a cvedexd\n" +
			"agent token rather than your CNA key: their writes then wait for your approval.",
		Example: "  claude mcp add cvedex -- cvedex mcp",
		GroupID: groupTools,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return mcpserver.New(a.client, Version).Run(cmd.Context(), &mcp.IOTransport{
				Reader: io.NopCloser(a.stdin),
				Writer: nopWriteCloser{a.stdout},
			})
		},
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
