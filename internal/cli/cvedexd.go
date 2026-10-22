package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/render"
)

func (a *app) cvedexdCommands() []*cobra.Command {
	review := &cobra.Command{
		Use:   "review",
		Short: "List the records submitters sent for review",
		Args:  cobra.NoArgs,
		RunE: a.onCvedexd(func(cmd *cobra.Command, _ []string) error {
			items, err := a.client.Review(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(items, func() string {
				if len(items) == 0 {
					return "Nothing to review."
				}
				rows := make([][]string, len(items))
				for i, item := range items {
					rows[i] = []string{item.CVEID, item.Submitter, day(item.UpdatedAt), title(item.Record)}
				}
				return render.Table([]string{"CVE ID", "SUBMITTER", "SENT", "TITLE"}, rows, nil)
			})
		}),
	}
	review.AddCommand(
		&cobra.Command{
			Use:   "show <CVE-ID>",
			Short: "Show a record in review",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				items, err := a.client.Review(cmd.Context())
				if err != nil {
					return err
				}
				id := cveID(args[0])
				for _, item := range items {
					if item.CVEID == id {
						return a.output(item, func() string {
							return render.Bold.Render(id) + render.Faint.Render("  from "+item.Submitter) + "\n\n" +
								render.Record(item.Record, a.width())
						})
					}
				}
				return fmt.Errorf("%s is not in review", id)
			}),
		},
		&cobra.Command{
			Use:   "approve <CVE-ID>",
			Short: "Publish a record in review, with your CVE Services key",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				id := cveID(args[0])
				record, err := a.client.Approve(cmd.Context(), id)
				if err != nil {
					return err
				}
				return a.output(record, func() string {
					return render.Good.Render("Published "+id) + "\n\n" + render.Record(record, a.width())
				})
			}),
		},
		&cobra.Command{
			Use:     "request-changes <CVE-ID> <note>",
			Short:   "Send a record back to its submitter with a note",
			Example: "  cvedex review request-changes CVE-2026-1234 \"Add the CWE.\"",
			Args:    cobra.ExactArgs(2),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				id := cveID(args[0])
				if err := a.client.RequestChanges(cmd.Context(), id, args[1]); err != nil {
					return err
				}
				return a.output(map[string]string{"cve_id": id, "note": args[1]}, func() string {
					return "Sent " + render.Bold.Render(id) + " back to its submitter."
				})
			}),
		},
	)

	proposals := &cobra.Command{
		Use:   "proposals",
		Short: "List the writes your agent tokens made, waiting for you",
		Args:  cobra.NoArgs,
		RunE: a.onCvedexd(func(cmd *cobra.Command, _ []string) error {
			list, err := a.client.Proposals(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(list, func() string {
				if len(list) == 0 {
					return "No pending proposals."
				}
				rows := make([][]string, len(list))
				for i, p := range list {
					rows[i] = []string{p.ID, p.Method + " " + p.Path, day(p.CreatedAt)}
				}
				return render.Table([]string{"ID", "REQUEST", "CREATED"}, rows, nil)
			})
		}),
	}
	proposals.AddCommand(
		&cobra.Command{
			Use:   "approve <proposal-id>",
			Short: "Send a proposal to CVE Services as yourself",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				body, err := a.client.ApproveProposal(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return a.output(body, func() string { return render.Good.Render("Approved proposal " + args[0]) })
			}),
		},
		&cobra.Command{
			Use:   "deny <proposal-id>",
			Short: "Discard a proposal",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				if err := a.client.DenyProposal(cmd.Context(), args[0]); err != nil {
					return err
				}
				return a.output(map[string]string{"id": args[0], "status": "denied"}, func() string {
					return "Denied proposal " + args[0] + "."
				})
			}),
		},
	)

	var filter cveservices.AuditFilter
	audit := &cobra.Command{
		Use:     "audit",
		Short:   "Show who did what on cvedexd, newest first",
		Example: "  cvedex audit --user alice@acme.org --since 2026-01-01",
		Args:    cobra.NoArgs,
		RunE: a.onCvedexd(func(cmd *cobra.Command, _ []string) error {
			entries, err := a.client.Audit(cmd.Context(), filter)
			if err != nil {
				return err
			}
			return a.output(entries, func() string {
				rows := make([][]string, len(entries))
				for i, e := range entries {
					rows[i] = []string{strings.Replace(e.Time[:min(len(e.Time), 19)], "T", " ", 1), deref(e.Actor),
						deref(e.ActorKind), e.Method + " " + e.Path, strconv.Itoa(e.Status)}
				}
				return render.Table(
					[]string{"TIME", "ACTOR", "AS", "REQUEST", "STATUS"},
					rows,
					func(row, col int) lipgloss.Style {
						if col == 4 && entries[row].Status >= 400 {
							return render.Bad
						}
						return lipgloss.NewStyle()
					},
				)
			})
		}),
	}
	audit.Flags().StringVar(&filter.User, "user", "", "only this actor")
	audit.Flags().StringVar(&filter.Since, "since", "", "only from this date or time on, such as 2026-01-31")

	submitter := &cobra.Command{
		Use:   "submitter",
		Short: "Manage submitters: people who reserve IDs and send records for review",
	}
	var agent bool
	token := &cobra.Command{
		Use:   "token <submitter-id>",
		Short: "Issue a new token for a submitter",
		Long: "Issues a new token for a submitter. With --agent, the token is for an AI agent: its writes wait\n" +
			"as proposals until the submitter approves them.",
		Args: cobra.ExactArgs(1),
		RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("submitter ID must be a number, not %q", args[0])
			}
			kind := "user"
			if agent {
				kind = "agent"
			}
			t, err := a.client.NewToken(cmd.Context(), id, kind)
			if err != nil {
				return err
			}
			return a.output(t, func() string { return tokenText(t.Kind, t.Token) })
		}),
	}
	token.Flags().BoolVar(&agent, "agent", false, "issue an agent token")
	submitter.AddCommand(
		&cobra.Command{
			Use:   "add <name>",
			Short: "Create a submitter and its first token",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				s, err := a.client.AddSubmitter(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				return a.output(s, func() string {
					created := fmt.Sprintf("Created submitter %s (ID %d)", s.Name, s.ID)
					return render.Good.Render(created) + "\n" + tokenText(s.Kind, s.Token.Token)
				})
			}),
		},
		token,
	)

	cmds := []*cobra.Command{review, proposals, audit, submitter}
	for _, cmd := range cmds {
		cmd.GroupID = groupCvedexd
	}
	return cmds
}

// onCvedexd checks the server is cvedexd before running, so pointing these commands at plain
// CVE Services fails with a clear message instead of a 404.
func (a *app) onCvedexd(run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		health, err := a.client.Health(cmd.Context())
		if err != nil {
			return err
		}
		if !health.IsCvedexd() {
			url := a.client.Credentials.URL
			return fmt.Errorf("%s needs a cvedexd server, and %s is plain CVE Services", cmd.CommandPath(), url)
		}
		return run(cmd, args)
	}
}

func tokenText(kind, token string) string {
	return fmt.Sprintf("New %s token:\n  %s\n%s", kind, token, render.Faint.Render("It is shown once. Store it now."))
}

// title reads the title of a record as a submitter sent it, {"cnaContainer": {...}}.
func title(record json.RawMessage) string {
	var r struct {
		CNA struct {
			Title string `json:"title"`
		} `json:"cnaContainer"`
	}
	_ = json.Unmarshal(record, &r)
	return r.CNA.Title
}

func day(timestamp string) string {
	d, _, _ := strings.Cut(timestamp, "T")
	return d
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
