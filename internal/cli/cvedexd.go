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
	cmds := []*cobra.Command{a.reviewCommand(), a.proposalsCommand(), a.auditCommand(), a.submitterCommand()}
	for _, cmd := range cmds {
		cmd.GroupID = groupCvedexd
	}
	return cmds
}

func (a *app) reviewCommand() *cobra.Command {
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
					rows[i] = []string{item.CVEID, item.Action, strconv.Itoa(item.Revision), item.Submitter,
						day(item.UpdatedAt), title(item.Record)}
				}
				return render.Table([]string{"CVE ID", "ACTION", "REV", "SUBMITTER", "SENT", "TITLE"}, rows, nil)
			})
		}),
	}
	var revision int
	approve := &cobra.Command{
		Use:   "approve <CVE-ID> --revision <n>",
		Short: "Publish or reject a record in review, with your CVE Services key",
		Long: "Publishes a record in review, or rejects the ID when the submitter asked to. --revision is the\n" +
			"one cvedex review show printed: if the submitter changed the record since, nothing is published.",
		Example: "  cvedex review approve CVE-2026-1234 --revision 2",
		Args:    cobra.ExactArgs(1),
		RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
			id := cveID(args[0])
			record, err := a.client.Approve(cmd.Context(), id, revision)
			if err != nil {
				return err
			}
			return a.output(record, func() string {
				return render.Good.Render("Approved "+id) + "\n\n" + render.Record(record, a.width())
			})
		}),
	}
	approve.Flags().IntVar(&revision, "revision", 0, "the revision you reviewed")
	_ = approve.MarkFlagRequired("revision") // the flag exists
	requestChanges := &cobra.Command{
		Use:     "request-changes <CVE-ID> <note> --revision <n>",
		Short:   "Send a record back to its submitter with a note",
		Example: "  cvedex review request-changes CVE-2026-1234 \"Add the CWE.\" --revision 2",
		Args:    cobra.ExactArgs(2),
		RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
			id := cveID(args[0])
			if err := a.client.RequestChanges(cmd.Context(), id, revision, args[1]); err != nil {
				return err
			}
			return a.output(map[string]string{"cve_id": id, "note": args[1]}, func() string {
				return "Sent " + render.Bold.Render(id) + " back to its submitter."
			})
		}),
	}
	requestChanges.Flags().IntVar(&revision, "revision", 0, "the revision you reviewed")
	_ = requestChanges.MarkFlagRequired("revision") // the flag exists
	review.AddCommand(
		&cobra.Command{
			Use:   "show <CVE-ID>",
			Short: "Show a record in review: a summary, what changed, and every field",
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
							return render.Review(item, a.width()) + "\n\n" + hint("Approve with ",
								fmt.Sprintf("cvedex review approve %s --revision %d", id, item.Revision))
						})
					}
				}
				return fmt.Errorf("%s is not in review", id)
			}),
		},
		approve,
		requestChanges,
	)
	return review
}

func (a *app) proposalsCommand() *cobra.Command {
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
				return render.Table([]string{"ID", "REQUEST", "CREATED"}, rows, nil) + "\n" +
					hint("See what one sends with ", "cvedex proposals show <id>")
			})
		}),
	}
	proposals.AddCommand(
		&cobra.Command{
			Use:   "show <proposal-id>",
			Short: "Show the request a proposal sends, body included",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				list, err := a.client.Proposals(cmd.Context())
				if err != nil {
					return err
				}
				for _, p := range list {
					if p.ID == args[0] {
						return a.output(p, func() string { return render.Proposal(p) })
					}
				}
				return fmt.Errorf("no pending proposal %s", args[0])
			}),
		},
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
	return proposals
}

func (a *app) auditCommand() *cobra.Command {
	var filter cveservices.AuditFilter
	audit := &cobra.Command{
		Use:     "audit",
		Short:   "Show who did what on cvedexd, newest first",
		Example: "  cvedex audit --user alice@acme.org --since 2026-01-01",
		Args:    cobra.NoArgs,
		RunE: a.onCvedexd(func(cmd *cobra.Command, _ []string) error {
			page, err := a.client.Audit(cmd.Context(), filter)
			if err != nil {
				return err
			}
			return a.output(page, func() string {
				entries := page.Entries
				rows := make([][]string, len(entries))
				for i, e := range entries {
					rows[i] = []string{strings.Replace(e.Time[:min(len(e.Time), 19)], "T", " ", 1), e.Actor,
						e.ActorKind, e.Method + " " + e.Path, status(e.Status)}
				}
				text := render.Table(
					[]string{"TIME", "ACTOR", "AS", "REQUEST", "STATUS"},
					rows,
					func(row, col int) lipgloss.Style {
						if s := entries[row].Status; col == 4 && (s == nil || *s >= 400) {
							return render.Bad
						}
						return lipgloss.NewStyle()
					},
				)
				if page.Next != nil {
					text += "\n" + hint("Older entries: ", fmt.Sprintf("cvedex audit --before %d", *page.Next))
				}
				return text
			})
		}),
	}
	audit.Flags().StringVar(&filter.User, "user", "", "only this actor")
	audit.Flags().StringVar(&filter.Since, "since", "", "only from this date or time on, such as 2026-01-31")
	audit.Flags().IntVar(&filter.Before, "before", 0, "only entries older than this one, to page back")
	return audit
}

// status is an audit entry's response status, or ? for a request that never finished.
func status(s *int) string {
	if s == nil {
		return "?"
	}
	return strconv.Itoa(*s)
}

func (a *app) submitterCommand() *cobra.Command {
	submitter := &cobra.Command{
		Use:   "submitter",
		Short: "Manage submitters: people who reserve IDs and send records for review",
		Args:  cobra.NoArgs,
		RunE: a.onCvedexd(func(cmd *cobra.Command, _ []string) error {
			list, err := a.client.Submitters(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(list, func() string {
				if len(list) == 0 {
					return "No submitters. Add one with " + render.Accent.Render("cvedex submitter add <name>") + "."
				}
				rows := make([][]string, len(list))
				for i, s := range list {
					rows[i] = []string{strconv.Itoa(s.ID), s.Name, enabled(s.DisabledAt), strconv.Itoa(s.OpenIDs),
						strconv.Itoa(s.Tokens), day(s.CreatedAt)}
				}
				return render.Table([]string{"ID", "NAME", "STATUS", "OPEN IDS", "TOKENS", "CREATED"}, rows,
					func(row, col int) lipgloss.Style {
						if list[row].DisabledAt != nil {
							return render.Faint
						}
						return lipgloss.NewStyle()
					})
			})
		}),
	}
	var agent bool
	token := &cobra.Command{
		Use:   "token <submitter-id>",
		Short: "Issue a new token for a submitter",
		Long: "Issues a new token for a submitter. With --agent, the token is for an AI agent: its writes wait\n" +
			"as proposals until the submitter approves them.",
		Args: cobra.ExactArgs(1),
		RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
			id, err := number("submitter", args[0])
			if err != nil {
				return err
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
	setDisabled := func(use, short string, disabled bool) *cobra.Command {
		return &cobra.Command{
			Use:   use + " <submitter-id>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				id, err := number("submitter", args[0])
				if err != nil {
					return err
				}
				s, err := a.client.SetSubmitterDisabled(cmd.Context(), id, disabled)
				if err != nil {
					return err
				}
				return a.output(s, func() string {
					return fmt.Sprintf("%s is %s.", render.Bold.Render(render.Clean(s.Name)), enabled(s.DisabledAt))
				})
			}),
		}
	}
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
		setDisabled("disable", "Stop a submitter's tokens and deny its pending proposals", true),
		setDisabled("enable", "Let a disabled submitter in again", false),
		token,
		&cobra.Command{
			Use:   "tokens <submitter-id>",
			Short: "List a submitter's tokens",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				id, err := number("submitter", args[0])
				if err != nil {
					return err
				}
				list, err := a.client.Tokens(cmd.Context(), id)
				if err != nil {
					return err
				}
				return a.output(list, func() string {
					rows := make([][]string, len(list))
					for i, t := range list {
						rows[i] = []string{strconv.Itoa(t.ID), t.Kind, day(t.CreatedAt), day(deref(t.LastUsedAt)),
							day(deref(t.RevokedAt))}
					}
					return render.Table([]string{"ID", "KIND", "CREATED", "LAST USED", "REVOKED"}, rows, nil)
				})
			}),
		},
		&cobra.Command{
			Use:   "revoke <token-id>",
			Short: "Stop a token at once and deny the proposals it made",
			Args:  cobra.ExactArgs(1),
			RunE: a.onCvedexd(func(cmd *cobra.Command, args []string) error {
				id, err := number("token", args[0])
				if err != nil {
					return err
				}
				t, err := a.client.RevokeToken(cmd.Context(), id)
				if err != nil {
					return err
				}
				return a.output(t, func() string { return fmt.Sprintf("Revoked token %d.", t.ID) })
			}),
		},
	)
	return submitter
}

func number(what, arg string) (int, error) {
	id, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("%s ID must be a number, not %q", what, arg)
	}
	return id, nil
}

func enabled(disabledAt *string) string {
	if disabledAt != nil {
		return "disabled"
	}
	return "enabled"
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
