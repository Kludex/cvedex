package cli

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"charm.land/huh/v2"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/config"
	"github.com/Kludex/cvedex/internal/render"
)

var noAuth = map[string]string{annotationNoAuth: "true"}

func (a *app) loginCommand() *cobra.Command {
	var test bool
	var org, user, key string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Check and save your CVE Services credentials",
		Long: "Asks for your CNA short name, username and API key, checks them against CVE Services, and\n" +
			"saves them to ~/.config/cvedex/config.json, readable by you only.\n\n" +
			"Without a terminal, pass --org and --user and pipe the API key on stdin.",
		Example: "  cvedex login\n  cvedex login --test\n" +
			"  echo \"$CVE_API_KEY\" | cvedex login --test --org acme --user alice@acme.org",
		Annotations: noAuth,
		GroupID:     groupStart,
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			creds := a.client.Credentials
			chooseURL := a.url == "" && !test
			if test {
				creds.URL = cveservices.TestURL
			}
			if org != "" {
				creds.Org = org
			}
			if user != "" {
				creds.User = user
			}
			creds.Key = key
			var err error
			if a.interactive() {
				err = a.loginForm(cmd, &creds, chooseURL)
			} else {
				err = a.loginFromFlags(&creds)
			}
			if err != nil {
				return err
			}
			client := cveservices.New(creds)
			me, err := client.User(cmd.Context(), creds.User)
			role := ""
			var apiErr *cveservices.Error
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
				// cvedexd refuses user lookups to submitters, so a 403 from it proves the token.
				if health, healthErr := client.Health(cmd.Context()); healthErr == nil && health.IsCvedexd() {
					me, err, role = &cveservices.User{}, nil, ", submitter"
				}
			}
			if err != nil {
				return err
			}
			inKeychain, err := config.Save(a.configPath, creds)
			if err != nil {
				return err
			}
			saved := "Saved to " + a.configPath + ", with the API key in the system keychain"
			if !inKeychain {
				saved = "Saved to " + a.configPath + ". There is no system keychain, so the API key is in that file"
			}
			a.print(render.Good.Render("Logged in") + " to " + creds.URL + " as " + render.Bold.Render(creds.User) +
				" (" + creds.Org + roles(me.Authority) + role + ").\n" + render.Faint.Render(saved))
			return nil
		},
	}
	cmd.Flags().BoolVar(&test, "test", false, "use MITRE's test instance, "+cveservices.TestURL)
	cmd.Flags().StringVar(&org, "org", "", "your CNA's short name")
	cmd.Flags().StringVar(&user, "user", "", "your CVE Services username, usually an email")
	cmd.Flags().StringVar(&key, "key", "", "your API key; prefer the prompt or stdin, which stay out of shell history")
	return cmd
}

func (a *app) loginForm(cmd *cobra.Command, creds *cveservices.Credentials, chooseURL bool) error {
	const other = "other"
	instance, custom := creds.URL, creds.URL
	if instance != cveservices.TestURL && instance != cveservices.ProductionURL {
		instance = other
	}
	required := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("required")
		}
		return nil
	}
	form := huh.NewForm(
		huh.NewGroup(huh.NewSelect[string]().
			Title("Which CVE Services?").
			Options(
				huh.NewOption("MITRE test instance  "+cveservices.TestURL, cveservices.TestURL),
				huh.NewOption("MITRE production     "+cveservices.ProductionURL, cveservices.ProductionURL),
				huh.NewOption("Another server, such as cvedexd", other),
			).
			Value(&instance)).
			WithHideFunc(func() bool { return !chooseURL }),
		huh.NewGroup(huh.NewInput().Title("Server URL").Value(&custom).Validate(func(s string) error {
			return checkURL(strings.TrimSpace(s))
		})).
			WithHideFunc(func() bool { return !chooseURL || instance != other }),
		huh.NewGroup(
			huh.NewInput().Title("CNA short name").Value(&creds.Org).Validate(required),
			huh.NewInput().Title("Username").Description("Usually the email you use for CVE Services").
				Value(&creds.User).Validate(required),
			huh.NewInput().Title("API key").EchoMode(huh.EchoModePassword).Value(&creds.Key).Validate(required),
		),
	).WithInput(a.stdin).WithOutput(a.stderr)
	if err := form.RunWithContext(cmd.Context()); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return errors.New("login cancelled")
		}
		return err
	}
	if chooseURL {
		creds.URL = instance
		if instance == other {
			creds.URL = strings.TrimSpace(custom)
		}
	}
	creds.Org = strings.TrimSpace(creds.Org)
	creds.User = strings.TrimSpace(creds.User)
	creds.Key = strings.TrimSpace(creds.Key)
	return nil
}

func (a *app) loginFromFlags(creds *cveservices.Credentials) error {
	if creds.Key == "" {
		line, err := bufio.NewReader(a.stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no API key: pipe it on stdin, or run cvedex login in a terminal")
		}
		creds.Key = strings.TrimSpace(line)
	}
	var missing []string
	if creds.Org == "" {
		missing = append(missing, "--org")
	}
	if creds.User == "" {
		missing = append(missing, "--user")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s; run cvedex login in a terminal to be asked", strings.Join(missing, " and "))
	}
	return nil
}

func roles(auth cveservices.Authority) string {
	if len(auth.ActiveRoles) == 0 {
		return ""
	}
	return ", " + strings.Join(auth.ActiveRoles, ", ")
}

func (a *app) logoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "logout",
		Short:       "Forget the saved credentials, the API key in the system keychain included",
		Annotations: noAuth,
		GroupID:     groupStart,
		Args:        cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			creds, err := config.Remove(a.configPath)
			if err != nil {
				return err
			}
			creds.Key = ""
			return a.output(creds, func() string {
				if creds.User == "" {
					return "You were not logged in."
				}
				return render.Good.Render("Logged out") + " of " + creds.URL + " as " + render.Bold.Render(creds.User) + "."
			})
		},
	}
}

func (a *app) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "status",
		Aliases:     []string{"ping", "whoami"},
		Short:       "Show which server you use and who you are logged in as",
		Annotations: noAuth,
		GroupID:     groupStart,
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			creds := a.client.Credentials
			health, err := a.client.Health(cmd.Context())
			if err != nil {
				return err
			}
			type status struct {
				URL     string            `json:"url"`
				Server  string            `json:"server"`
				Version string            `json:"version,omitempty"`
				User    *cveservices.User `json:"user,omitempty"`
				Org     *cveservices.Org  `json:"org,omitempty"`
				// Submitter is set for a cvedexd submitter, who has no CVE Services account.
				Submitter string `json:"submitter,omitempty"`
			}
			s := status{URL: creds.URL, Server: "CVE Services", Version: health.Version}
			if health.IsCvedexd() {
				s.Server = "cvedexd"
			}
			if creds.Org != "" && creds.User != "" && creds.Key != "" {
				s.User, err = a.client.User(cmd.Context(), creds.User)
				var apiErr *cveservices.Error
				switch {
				case health.IsCvedexd() && errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden:
					s.User, s.Submitter = nil, creds.User
				case err != nil:
					return err
				default:
					if s.Org, err = a.client.Org(cmd.Context()); err != nil {
						return err
					}
				}
			}
			return a.output(s, func() string {
				server := s.Server
				if s.Version != "" {
					server += " " + s.Version
				}
				lines := []string{render.Label.Render("Server") + render.Good.Render("● ") + creds.URL +
					render.Faint.Render("  "+server)}
				if s.Submitter != "" {
					user := render.Bold.Render(s.Submitter) + render.Faint.Render("  submitter")
					return strings.Join(append(lines, render.Label.Render("User")+user), "\n")
				}
				if s.User == nil {
					user := render.Warn.Render("not logged in") + hint(", run ", "cvedex login")
					return strings.Join(append(lines, render.Label.Render("User")+user), "\n")
				}
				user := render.Bold.Render(s.User.Username) + render.Faint.Render(strings.TrimPrefix(roles(s.User.Authority), ","))
				org := s.Org.Name + render.Faint.Render(" ("+s.Org.ShortName+")")
				lines = append(lines, render.Label.Render("User")+user, render.Label.Render("CNA")+org)
				return strings.Join(lines, "\n")
			})
		},
	}
}
