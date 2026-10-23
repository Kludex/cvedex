package cli

import (
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/internal/tui"
)

func (a *app) tuiCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "tui",
		Short:   "Browse CVE IDs, records and, on cvedexd, reviews in a full-screen interface",
		GroupID: groupTools,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return tui.Run(cmd.Context(), a.client, a.stdin, a.stdout)
		},
	}
}
