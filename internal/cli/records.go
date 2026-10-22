package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"charm.land/huh/v2"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/render"
)

func (a *app) recordCommands() []*cobra.Command {
	cmds := []*cobra.Command{a.reserveCommand(), a.listCommand(), a.showCommand(),
		a.writeCommand("publish", "Publish the record of a reserved CVE ID", a.publish),
		a.writeCommand("update", "Replace the record of a published CVE ID", a.update),
		a.rejectCommand()}
	for _, cmd := range cmds {
		cmd.GroupID = groupRecords
	}
	return cmds
}

func (a *app) reserveCommand() *cobra.Command {
	var opts cveservices.ReserveOptions
	cmd := &cobra.Command{
		Use:     "reserve",
		Short:   "Reserve CVE IDs for your CNA",
		Example: "  cvedex reserve\n  cvedex reserve --count 3 --sequential\n  cvedex reserve --year 2025",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := a.client.Reserve(cmd.Context(), opts)
			if err != nil {
				return err
			}
			return a.output(ids, func() string {
				lines := []string{render.Good.Render(fmt.Sprintf("Reserved %d CVE %s", len(ids), plural(len(ids), "ID", "IDs")))}
				for _, id := range ids {
					lines = append(lines, "  "+render.Bold.Render(id.ID))
				}
				if len(ids) > 0 {
					lines = append(lines, hint("Publish with ", "cvedex publish "+ids[0].ID+" record.json"))
				}
				return strings.Join(lines, "\n")
			})
		},
	}
	cmd.Flags().IntVar(&opts.Year, "year", time.Now().Year(), "year of the IDs")
	cmd.Flags().IntVarP(&opts.Count, "count", "n", 1, "how many IDs to reserve")
	cmd.Flags().BoolVar(&opts.Sequential, "sequential", false, "ask for consecutive IDs")
	return cmd
}

func (a *app) listCommand() *cobra.Command {
	var state string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List your CNA's CVE IDs",
		Example: "  cvedex list\n  cvedex list --state reserved",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state = strings.ToUpper(state)
			switch state {
			case "", cveservices.StateReserved, cveservices.StatePublished, cveservices.StateRejected:
			default:
				return fmt.Errorf("--state must be reserved, published or rejected, not %q", state)
			}
			ids, err := a.client.ListIDs(cmd.Context(), state)
			if err != nil {
				return err
			}
			return a.output(ids, func() string {
				if len(ids) == 0 {
					return "No CVE IDs. Reserve one with " + render.Accent.Render("cvedex reserve") + "."
				}
				return render.IDs(ids)
			})
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "only IDs in this state: reserved, published or rejected")
	return cmd
}

func (a *app) showCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "show <CVE-ID>",
		Short:   "Show a CVE record",
		Long:    "Shows a summary of a CVE record. With --json, prints the record as CVE Services returns it.",
		Example: "  cvedex show CVE-2026-1234\n  cvedex show 2026-1234 --json > record.json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			record, err := a.client.Record(cmd.Context(), cveID(args[0]))
			if err != nil {
				return err
			}
			return a.output(record, func() string { return render.Record(record, a.width()) })
		},
	}
}

type writeFunc func(cmd *cobra.Command, id string, cna json.RawMessage) (json.RawMessage, error)

func (a *app) writeCommand(name, short string, send writeFunc) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   name + " <CVE-ID> <record.json>",
		Short: short,
		Long: short + ".\n\nThe file holds the CNA container, either bare, as {\"cnaContainer\": ...}, or as a full\n" +
			"record such as `cvedex show --json` prints. Pass - to read it from stdin.",
		Example: "  cvedex " + name + " CVE-2026-1234 record.json\n" +
			"  cat record.json | cvedex " + name + " CVE-2026-1234 -",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cna, err := a.readContainer(args[1])
			if err != nil {
				return err
			}
			return a.write(cmd, name, cveID(args[0]), cna, yes, send)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation on MITRE production")
	return cmd
}

func (a *app) rejectCommand() *cobra.Command {
	var yes bool
	var reason string
	cmd := &cobra.Command{
		Use:     "reject <CVE-ID> --reason <text>",
		Short:   "Reject a CVE ID",
		Long:    "Rejects a CVE ID, for example a duplicate or one that turned out not to be a vulnerability.",
		Example: "  cvedex reject CVE-2026-1234 --reason \"Duplicate of CVE-2026-1200.\"",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return errors.New("--reason is required")
			}
			reasons := []map[string]string{{"lang": "en", "value": reason}}
			cna, _ := json.Marshal(map[string]any{"rejectedReasons": reasons}) // strings always marshal
			return a.write(cmd, "reject", cveID(args[0]), cna, yes, a.reject)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why the ID is rejected, in English")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation on MITRE production")
	return cmd
}

func (a *app) write(cmd *cobra.Command, verb, id string, cna json.RawMessage, yes bool, send writeFunc) error {
	question := fmt.Sprintf("%s %s on %s? It will be public.", capitalize(verb), id, a.client.Credentials.URL)
	if !yes && a.client.Credentials.URL == cveservices.ProductionURL {
		if err := a.confirm(cmd, question); err != nil {
			return err
		}
	}
	record, err := send(cmd, id, cna)
	if err != nil {
		return err
	}
	return a.output(record, func() string {
		if cveservices.InReview(record) {
			return render.Good.Render("Sent " + id + " for review")
		}
		return render.Good.Render(capitalize(pastTense(verb))+" "+id) + "\n\n" + render.Record(record, a.width())
	})
}

func (a *app) publish(cmd *cobra.Command, id string, cna json.RawMessage) (json.RawMessage, error) {
	return a.client.Publish(cmd.Context(), id, cna)
}

func (a *app) reject(cmd *cobra.Command, id string, cna json.RawMessage) (json.RawMessage, error) {
	return a.client.Reject(cmd.Context(), id, cna)
}

func (a *app) update(cmd *cobra.Command, id string, cna json.RawMessage) (json.RawMessage, error) {
	return a.client.Update(cmd.Context(), id, cna)
}

// readContainer reads a CNA container from path, or stdin for -. It accepts the container bare,
// wrapped as {"cnaContainer": ...}, or inside a full record.
func (a *app) readContainer(path string) (json.RawMessage, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(a.stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		CNAContainer json.RawMessage `json:"cnaContainer"`
		Containers   struct {
			CNA json.RawMessage `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", path, err)
	}
	switch {
	case doc.CNAContainer != nil:
		return doc.CNAContainer, nil
	case doc.Containers.CNA != nil:
		return doc.Containers.CNA, nil
	}
	return data, nil
}

// confirm asks a yes/no question, and fails without a terminal to ask it in.
func (a *app) confirm(cmd *cobra.Command, question string) error {
	if !a.interactive() {
		return errors.New(cmd.Name() + " needs --yes when there is no terminal to ask")
	}
	var ok bool
	err := huh.NewForm(huh.NewGroup(huh.NewConfirm().Title(question).Value(&ok))).
		WithInput(a.stdin).WithOutput(a.stderr).RunWithContext(cmd.Context())
	if err != nil || !ok {
		return errors.New("cancelled")
	}
	return nil
}

var shortID = regexp.MustCompile(`^\d{4}-\d{4,}$`)

// cveID accepts an ID with or without the CVE- prefix, in any case.
func cveID(arg string) string {
	id := strings.ToUpper(strings.TrimSpace(arg))
	if shortID.MatchString(id) {
		return "CVE-" + id
	}
	return id
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func capitalize(s string) string {
	return strings.ToUpper(s[:1]) + s[1:]
}

func pastTense(verb string) string {
	if strings.HasSuffix(verb, "e") {
		return verb + "d"
	}
	return verb + "ed"
}
