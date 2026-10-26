package cli

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/internal/record"
	"github.com/Kludex/cvedex/internal/render"
)

func (a *app) recordCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:         "record",
		Short:       "Write a record to publish",
		Annotations: noAuth,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "check <record.json>",
		Short: "Check a record against the CVE JSON 5 schema",
		Long: "Checks a record against the CVE JSON 5 schema, as publish and update do before sending, and lists\n" +
			"every problem. The file holds the CNA container, bare, wrapped or in a full record. Pass - to read it\n" +
			"from stdin.",
		Example: "  cvedex record check record.json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := a.readChecked(args[0]); err != nil {
				return err
			}
			return a.output(map[string]bool{"valid": true}, func() string {
				return render.Good.Render("The record is a valid CNA container")
			})
		},
	}, &cobra.Command{
		Use:   "from-advisory <url>",
		Short: "Write a record from a GitHub repository advisory",
		Long: "Fetches a GitHub repository advisory and prints the CNA container of a record built from it:\n" +
			"title, description, affected versions, CWEs, CVSS scores, credits and references. Edit it, then\n" +
			"publish it.\n\n" +
			"Published advisories need no token. A draft needs your GitHub login: GH_TOKEN or GITHUB_TOKEN,\n" +
			"else the GitHub CLI's, from gh auth login.",
		Example: "  cvedex record from-advisory " + record.AdvisoryHint + " > record.json\n" +
			"  cvedex publish CVE-2026-1234 record.json",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cna, err := record.FromAdvisory(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(a.stdout, string(cna))
			if invalid, ok := record.Check(cna).(*record.InvalidError); ok {
				_, _ = lipgloss.Fprintln(a.stderr, render.Warn.Render("Edit it before you publish.")+
					" It is "+invalid.Error()+":\n"+problems(invalid))
			}
			return nil
		},
	})
	return cmd
}

func problems(invalid *record.InvalidError) string {
	return render.Clean("  " + strings.Join(invalid.Problems, "\n  "))
}
