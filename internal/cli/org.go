package cli

import (
	"errors"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/spf13/cobra"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/render"
)

func (a *app) orgCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "org",
		Short:   "Show your CNA and manage its users",
		GroupID: groupOrg,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			org, err := a.client.Org(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(org, func() string {
				return strings.Join([]string{
					render.Bold.Render(org.Name) + render.Faint.Render("  "+org.ShortName),
					render.Label.Render("Roles") + strings.Join(org.Authority.ActiveRoles, ", "),
					render.Label.Render("ID quota") + fmt.Sprint(org.Policies.IDQuota),
				}, "\n")
			})
		},
	}
	cmd.AddCommand(a.quotaCommand(), a.usersCommand(), a.addUserCommand(), a.updateUserCommand(), a.resetKeyCommand())
	return cmd
}

func (a *app) quotaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "quota",
		Short: "Show how many CVE IDs your CNA may still reserve",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			quota, err := a.client.Quota(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(quota, func() string {
				return strings.Join([]string{
					render.Label.Render("Quota") + fmt.Sprint(quota.Quota),
					render.Label.Render("Reserved") + fmt.Sprint(quota.Reserved),
					render.Label.Render("Available") + fmt.Sprint(quota.Available),
				}, "\n")
			})
		},
	}
}

func (a *app) usersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "users",
		Short: "List your CNA's users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			users, err := a.client.Users(cmd.Context())
			if err != nil {
				return err
			}
			return a.output(users, func() string {
				rows := make([][]string, len(users))
				for i, u := range users {
					active := "active"
					if !u.Active {
						active = "inactive"
					}
					rows[i] = []string{u.Username, strings.TrimSpace(u.Name.First + " " + u.Name.Last),
						strings.Join(u.Authority.ActiveRoles, ", "), active}
				}
				return render.Table(
					[]string{"USERNAME", "NAME", "ROLES", "STATUS"},
					rows,
					func(row, col int) lipgloss.Style {
						if col == 3 && !users[row].Active {
							return render.Faint
						}
						return lipgloss.NewStyle()
					},
				)
			})
		},
	}
}

func (a *app) addUserCommand() *cobra.Command {
	var user cveservices.User
	var admin bool
	cmd := &cobra.Command{
		Use:     "add-user <username>",
		Short:   "Add a user to your CNA (admins only)",
		Example: "  cvedex org add-user bob@acme.org --first Bob --last Smith",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			user.Username = args[0]
			if admin {
				user.Authority.ActiveRoles = []string{"ADMIN"}
			}
			created, err := a.client.AddUser(cmd.Context(), user)
			if err != nil {
				return err
			}
			return a.output(created, func() string {
				return render.Good.Render("Added "+created.Username) + "\n" +
					hint("Give them an API key with ", "cvedex org reset-key "+created.Username)
			})
		},
	}
	cmd.Flags().StringVar(&user.Name.First, "first", "", "first name")
	cmd.Flags().StringVar(&user.Name.Last, "last", "", "last name")
	cmd.Flags().BoolVar(&admin, "admin", false, "make the user an org admin")
	return cmd
}

func (a *app) updateUserCommand() *cobra.Command {
	var update cveservices.UserUpdate
	var admin, active bool
	cmd := &cobra.Command{
		Use:   "update-user <username>",
		Short: "Change a user's name, username, admin role or status",
		Long: "Changes a user of your CNA. You can change your own name; only org admins can change the rest.\n" +
			"A deactivated user's API key stops working until they are activated again.",
		Example: "  cvedex org update-user bob@acme.org --last Jones\n" +
			"  cvedex org update-user bob@acme.org --active=false",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			if flags.Changed("admin") && admin {
				update.AddRole = "ADMIN"
			} else if flags.Changed("admin") {
				update.RemoveRole = "ADMIN"
			}
			if flags.Changed("active") {
				update.Active = &active
			}
			if update == (cveservices.UserUpdate{}) {
				return errors.New("nothing to change; pass --first, --last, --username, --admin or --active")
			}
			user, err := a.client.UpdateUser(cmd.Context(), args[0], update)
			if err != nil {
				return err
			}
			return a.output(user, func() string { return render.Good.Render("Updated " + render.Clean(user.Username)) })
		},
	}
	cmd.Flags().StringVar(&update.First, "first", "", "new first name")
	cmd.Flags().StringVar(&update.Last, "last", "", "new last name")
	cmd.Flags().StringVar(&update.NewUsername, "username", "", "new username")
	cmd.Flags().BoolVar(&admin, "admin", false, "make the user an org admin, or not with --admin=false")
	cmd.Flags().BoolVar(&active, "active", true, "activate the user, or deactivate with --active=false")
	return cmd
}

func (a *app) resetKeyCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset-key <username>",
		Short: "Issue a new API key for a user; the old one stops working at once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				if err := a.confirm(cmd, "Replace the API key of "+args[0]+"? The current key stops working."); err != nil {
					return err
				}
			}
			key, err := a.client.ResetKey(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.output(map[string]string{"username": args[0], "key": key}, func() string {
				return "New API key for " + render.Bold.Render(args[0]) + ":\n  " + key + "\n" +
					render.Faint.Render("It is shown once. Store it now.")
			})
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}
