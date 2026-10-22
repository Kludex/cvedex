// Package cli is the cvedex command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/config"
	"github.com/Kludex/cvedex/internal/render"
)

// Version is set at build time with -ldflags "-X github.com/Kludex/cvedex/internal/cli.Version=...".
var Version = "dev"

// Main runs cvedex with args and returns the process exit code.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cobra.EnableCommandSorting = false
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	root := a.root()
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	a.printError(err)
	return 1
}

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	json           bool
	url            string
	configPath     string
	client         *cveservices.Client
}

const (
	groupStart   = "start"
	groupRecords = "records"
	groupOrg     = "org"
	groupCvedexd = "cvedexd"
	groupTools   = "tools"
)

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use:   "cvedex",
		Short: "Reserve CVE IDs and publish CVE records",
		Long: "cvedex talks to CVE Services, the API CNAs use to reserve CVE IDs and publish records.\n" +
			"Point it at MITRE, MITRE's test instance, or a cvedexd policy server.",
		Example: "  cvedex login --test\n  cvedex reserve\n" +
			"  cvedex publish CVE-2026-1234 record.json\n  cvedex tui",
		Version:           Version,
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: a.connect,
	}
	root.PersistentFlags().BoolVar(&a.json, "json", false, "print JSON instead of text")
	root.PersistentFlags().StringVar(&a.url, "url", "", "CVE Services URL, overriding the saved one")
	root.AddGroup(
		&cobra.Group{ID: groupStart, Title: "Start here:"},
		&cobra.Group{ID: groupRecords, Title: "CVE IDs and records:"},
		&cobra.Group{ID: groupOrg, Title: "Your CNA:"},
		&cobra.Group{ID: groupCvedexd, Title: "cvedexd policy server:"},
		&cobra.Group{ID: groupTools, Title: "Interfaces:"},
	)
	root.AddCommand(a.loginCommand(), a.statusCommand())
	root.AddCommand(a.recordCommands()...)
	root.AddCommand(a.orgCommand())
	root.AddCommand(a.cvedexdCommands()...)
	root.AddCommand(a.tuiCommand(), a.mcpCommand())
	root.SetIn(a.stdin)
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.InitDefaultCompletionCmd()
	for _, cmd := range root.Commands() {
		if cmd.Name() == "completion" {
			cmd.Annotations = noAuth
		}
	}
	return root
}

// annotationNoAuth marks commands that run without saved credentials.
const annotationNoAuth = "noAuth"

func (a *app) connect(cmd *cobra.Command, _ []string) error {
	path, err := config.Path()
	if err != nil {
		return err
	}
	creds, err := config.Load(path)
	if err != nil {
		return err
	}
	if a.url != "" {
		creds.URL = a.url
	}
	a.configPath, a.client = path, cveservices.New(creds)
	if _, err := url.ParseRequestURI(a.client.Credentials.URL); err != nil {
		return fmt.Errorf("invalid URL %q", creds.URL)
	}
	needsAuth := true
	for c := cmd; c != nil; c = c.Parent() {
		needsAuth = needsAuth && c.Annotations[annotationNoAuth] == ""
	}
	if needsAuth && (creds.Org == "" || creds.User == "" || creds.Key == "") {
		return errNotLoggedIn
	}
	return nil
}

var errNotLoggedIn = errors.New("not logged in")

// print writes text, dropping colors when stdout is not a terminal.
func (a *app) print(text string) {
	_, _ = lipgloss.Fprintln(a.stdout, text)
}

// printJSON writes v as indented JSON.
func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// output prints v as JSON with --json, and text otherwise.
func (a *app) output(v any, text func() string) error {
	if a.json {
		return a.printJSON(v)
	}
	a.print(text())
	return nil
}

func (a *app) interactive() bool {
	f, ok := a.stdin.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

func (a *app) width() int {
	if f, ok := a.stdout.(*os.File); ok {
		if w, _, err := term.GetSize(f.Fd()); err == nil && w > 0 {
			return min(w, 100)
		}
	}
	return 80
}

func (a *app) printError(err error) {
	var apiErr *cveservices.Error
	var pending *cveservices.PendingApproval
	switch {
	case errors.As(err, &apiErr) && a.json:
		_, _ = fmt.Fprintln(a.stderr, strings.TrimSpace(string(apiErr.Body)))
	case errors.As(err, &apiErr):
		a.printAPIError(apiErr)
	case errors.As(err, &pending):
		_, _ = lipgloss.Fprintln(a.stderr, render.Warn.Render("Waiting for approval")+" as proposal "+
			render.Bold.Render(pending.ProposalID)+"\n"+hint("Approve it with ", "cvedex proposals approve "+pending.ProposalID))
	case errors.Is(err, errNotLoggedIn):
		_, _ = lipgloss.Fprintln(a.stderr, render.Bad.Render("Not logged in.")+" "+
			hint("Run ", "cvedex login")+render.Faint.Render(", or set CVE_API_ORG, CVE_API_USER and CVE_API_KEY."))
	default:
		_, _ = lipgloss.Fprintln(a.stderr, render.Bad.Render("Error:")+" "+err.Error())
	}
}

// hint suggests a command to run next.
func hint(text, command string) string {
	return render.Faint.Render(text) + render.Accent.Render(command)
}

func (a *app) printAPIError(e *cveservices.Error) {
	var b strings.Builder
	b.WriteString(render.Bad.Render("Error:") + " " + e.Error())
	for _, detail := range render.ErrorDetails(e.Details) {
		b.WriteString("\n  " + detail)
	}
	switch e.Status {
	case 401:
		b.WriteString("\n" + hint("Check your credentials with ", "cvedex status") + hint(" or ", "cvedex login"))
	case 403:
		b.WriteString("\n" + render.Faint.Render("Your user is not allowed to do this."))
	}
	_, _ = lipgloss.Fprintln(a.stderr, b.String())
}
