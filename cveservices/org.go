package cveservices

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// Org is a CNA as CVE Services knows it.
type Org struct {
	Name      string    `json:"name"`
	ShortName string    `json:"short_name"`
	UUID      string    `json:"UUID"`
	Authority Authority `json:"authority"`
	Policies  struct {
		IDQuota int `json:"id_quota"`
	} `json:"policies"`
}

// Authority lists the roles of an org or user, such as CNA or ADMIN.
type Authority struct {
	ActiveRoles []string `json:"active_roles"`
}

// User is a user of an org.
type User struct {
	Username  string    `json:"username"`
	UUID      string    `json:"UUID,omitempty"`
	OrgUUID   string    `json:"org_UUID,omitempty"`
	Name      Name      `json:"name"`
	Authority Authority `json:"authority"`
	Active    bool      `json:"active"`
}

// Name is a user's name.
type Name struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

// Quota is how many CVE IDs the org may hold in the RESERVED state, and how many it does.
type Quota struct {
	Quota     int `json:"id_quota"`
	Reserved  int `json:"total_reserved"`
	Available int `json:"available"`
}

// Quota returns the client's org's ID quota and its use.
func (c *Client) Quota(ctx context.Context) (*Quota, error) {
	var quota Quota
	err := c.Do(ctx, http.MethodGet, c.orgPath()+"/id_quota", nil, nil, &quota)
	return &quota, err
}

// Org returns the client's org.
func (c *Client) Org(ctx context.Context) (*Org, error) {
	var org Org
	err := c.Do(ctx, http.MethodGet, c.orgPath(), nil, nil, &org)
	return &org, err
}

// User returns one user of the client's org. CVE Services only answers it when the credentials
// are valid, so it also checks a login.
func (c *Client) User(ctx context.Context, username string) (*User, error) {
	var user User
	err := c.Do(ctx, http.MethodGet, c.orgPath()+"/user/"+url.PathEscape(username), nil, nil, &user)
	return &user, err
}

// Users returns every user of the client's org. It follows pagination.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	var users []User
	query := url.Values{}
	for {
		var page struct {
			Users    []User `json:"users"`
			NextPage *int   `json:"nextPage"`
		}
		if err := c.Do(ctx, http.MethodGet, c.orgPath()+"/users", query, nil, &page); err != nil {
			return nil, err
		}
		users = append(users, page.Users...)
		if page.NextPage == nil {
			return users, nil
		}
		query.Set("page", strconv.Itoa(*page.NextPage))
	}
}

// AddUser creates a user in the client's org. Only an org admin can. Username, Name and
// Authority are sent; the rest is set by CVE Services.
func (c *Client) AddUser(ctx context.Context, user User) (*User, error) {
	roles := user.Authority.ActiveRoles
	if roles == nil {
		roles = []string{}
	}
	body := map[string]any{"username": user.Username, "name": user.Name, "authority": Authority{ActiveRoles: roles}}
	var out struct {
		Created User `json:"created"`
	}
	err := c.Do(ctx, http.MethodPost, c.orgPath()+"/user", nil, body, &out)
	return &out.Created, err
}

// UserUpdate changes a user. Zero fields are left as they are.
type UserUpdate struct {
	// Active deactivates a user when false. A deactivated user's key stops working.
	Active      *bool
	First       string
	Last        string
	NewUsername string
	// AddRole and RemoveRole take ADMIN, the only role CVE Services lets an org admin change.
	AddRole    string
	RemoveRole string
}

// UpdateUser changes a user of the client's org and returns it. Users can change their own name;
// only an org admin can change the rest.
func (c *Client) UpdateUser(ctx context.Context, username string, update UserUpdate) (*User, error) {
	query := url.Values{}
	if update.Active != nil {
		query.Set("active", strconv.FormatBool(*update.Active))
	}
	for name, value := range map[string]string{
		"name.first":          update.First,
		"name.last":           update.Last,
		"new_username":        update.NewUsername,
		"active_roles.add":    update.AddRole,
		"active_roles.remove": update.RemoveRole,
	} {
		if value != "" {
			query.Set(name, value)
		}
	}
	var out struct {
		Updated User `json:"updated"`
	}
	err := c.Do(ctx, http.MethodPut, c.orgPath()+"/user/"+url.PathEscape(username), query, nil, &out)
	return &out.Updated, err
}

// ResetKey issues a new API key for a user of the client's org and returns it. The old key stops
// working at once.
func (c *Client) ResetKey(ctx context.Context, username string) (string, error) {
	var out struct {
		Secret string `json:"API-secret"`
	}
	err := c.Do(ctx, http.MethodPut, c.orgPath()+"/user/"+url.PathEscape(username)+"/reset_secret", nil, nil, &out)
	return out.Secret, err
}

func (c *Client) orgPath() string {
	return "/api/org/" + url.PathEscape(c.Credentials.Org)
}
