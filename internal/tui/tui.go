// Package tui is the full-screen cvedex interface: the CNA's CVE IDs and records and, against
// cvedexd, the review queue, proposals and audit log.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/render"
)

// Run shows the interface until the user quits.
func Run(ctx context.Context, client *cveservices.Client) error {
	_, err := tea.NewProgram(New(ctx, client), tea.WithContext(ctx)).Run()
	return err
}

type tab int

const (
	tabIDs tab = iota
	tabReview
	tabProposals
	tabAudit
)

// maxDetails is how many lines of an error's details the status area shows.
const maxDetails = 5

var tabNames = []string{"CVE IDs", "Review", "Proposals", "Audit"}

// Model is the interface's state. Drive it with tea messages.
type Model struct {
	ctx      context.Context
	client   *cveservices.Client
	tabs     []tab
	tab      tab
	table    table.Model
	reader   viewport.Model
	spinner  spinner.Model
	width    int
	height   int
	loading  bool
	reading  string
	flash    string
	err      error
	question string
	answer   tea.Cmd
	drafts   map[string]draft

	ids       []cveservices.CVEID
	review    []cveservices.ReviewItem
	proposals []cveservices.Proposal
	audit     []cveservices.AuditEntry
}

// New returns the interface for client. The CVE IDs tab loads first.
func New(ctx context.Context, client *cveservices.Client) Model {
	keys := table.DefaultKeyMap()
	keys.HalfPageUp.SetKeys("ctrl+u")
	keys.HalfPageDown.SetKeys("ctrl+d")
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Faint(true).Bold(false)
	styles.Selected = styles.Selected.Foreground(lipgloss.NoColor{}).Reverse(true).Bold(false)
	return Model{
		ctx:     ctx,
		client:  client,
		tabs:    []tab{tabIDs},
		table:   table.New(table.WithFocused(true), table.WithKeyMap(keys), table.WithStyles(styles)),
		reader:  viewport.New(),
		spinner: spinner.New(spinner.WithSpinner(spinner.Dot)),
		width:   100,
		height:  30,
		loading: true,
		drafts:  map[string]draft{},
	}
}

type (
	healthMsg struct {
		health cveservices.Health
		err    error
	}
	loadedMsg struct {
		tab  tab
		data any
		err  error
	}
	tabsMsg   []tab
	recordMsg struct {
		id     string
		record json.RawMessage
		err    error
	}
	doneMsg struct {
		flash string
		err   error
		// saved is the ID whose draft was sent.
		saved string
	}
)

// Init checks which kind of server it talks to, then loads the CVE IDs.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, func() tea.Msg {
		health, err := m.client.Health(m.ctx)
		return healthMsg{health, err}
	})
}

// Update applies one message.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case healthMsg:
		if !msg.health.IsCvedexd() {
			return m, m.load(tabIDs)
		}
		return m, m.allowedTabs
	case tabsMsg:
		m.tabs = msg
		return m, m.load(tabIDs)
	case loadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else if msg.tab == m.tab {
			m.show(msg.data)
		}
		return m, nil
	case recordMsg:
		m.loading, m.err = false, msg.err
		switch {
		case noRecord(msg.err):
			m.err, m.flash = nil, msg.id+" has no record yet. Press e to write one."
		case msg.err == nil:
			m.open(msg.id, msg.record)
		}
		return m, nil
	case draftMsg:
		m.loading, m.err = false, msg.err
		if msg.err != nil {
			return m, nil
		}
		m.drafts[msg.draft.id] = msg.draft
		return m, openEditor(msg.draft)
	case editedMsg:
		m.edited(msg)
		return m, nil
	case doneMsg:
		m.loading, m.err = false, msg.err
		if msg.err != nil {
			return m, nil
		}
		m.flash = msg.flash
		m.discard(msg.saved)
		if m.reading == msg.saved {
			m.reading = ""
		}
		return m, m.load(m.tab)
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

// allowedTabs finds the cvedexd tabs open to the caller: CNA users review and read the audit log,
// submitters approve their agents' proposals.
func (m Model) allowedTabs() tea.Msg {
	tabs := []tab{tabIDs}
	_, err := m.client.Review(m.ctx)
	reviewer := !forbidden(err)
	if reviewer {
		tabs = append(tabs, tabReview)
	}
	if _, err := m.client.Proposals(m.ctx); !forbidden(err) {
		tabs = append(tabs, tabProposals)
	}
	if reviewer {
		tabs = append(tabs, tabAudit)
	}
	return tabsMsg(tabs)
}

func forbidden(err error) bool {
	var apiErr *cveservices.Error
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden
}

func (m Model) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	if m.question != "" {
		answer := m.answer
		m.question, m.answer = "", nil
		if k == "y" {
			m.loading = true
			return m, answer
		}
		return m, nil
	}
	if k == "ctrl+c" || k == "q" {
		return m, tea.Quit
	}
	if m.reading != "" {
		switch {
		case k == "esc" || k == "backspace" || k == "left" || k == "h":
			m.reading = ""
			return m, nil
		case k == "e" && m.tab == tabIDs:
			m.flash, m.err, m.loading = "", nil, true
			return m, m.edit(m.reading)
		}
		var cmd tea.Cmd
		m.reader, cmd = m.reader.Update(msg)
		return m, cmd
	}
	m.flash, m.err = "", nil
	switch k {
	case "tab", "shift+tab":
		if len(m.tabs) == 1 {
			return m, nil
		}
		step := 1
		if k == "shift+tab" {
			step = len(m.tabs) - 1
		}
		return m, m.load(m.tabs[(m.position()+step)%len(m.tabs)])
	case "1", "2", "3", "4":
		if i := int(k[0] - '1'); i < len(m.tabs) {
			return m, m.load(m.tabs[i])
		}
	case "r":
		return m, m.load(m.tab)
	case "enter":
		return m, m.enter()
	case "e":
		if id, ok := pick(m.ids, m.table.Cursor(), m.tab == tabIDs); ok {
			m.loading = true
			return m, m.edit(id.ID)
		}
	case "n":
		if m.tab == tabIDs {
			year := time.Now().Year()
			m.ask(fmt.Sprintf("Reserve a CVE ID for %d?", year), func() tea.Msg {
				ids, err := m.client.Reserve(m.ctx, cveservices.ReserveOptions{Year: year})
				if err != nil || len(ids) == 0 {
					return doneMsg{err: err}
				}
				return doneMsg{flash: "Reserved " + ids[0].ID}
			})
		}
	case "a":
		m.approve()
	case "d":
		if p, ok := pick(m.proposals, m.table.Cursor(), m.tab == tabProposals); ok {
			m.ask("Deny proposal "+p.ID+"?", func() tea.Msg {
				return doneMsg{flash: "Denied proposal " + p.ID, err: m.client.DenyProposal(m.ctx, p.ID)}
			})
		}
	default:
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) approve() {
	if item, ok := pick(m.review, m.table.Cursor(), m.tab == tabReview); ok {
		m.ask("Publish "+item.CVEID+" with your key? It will be public.", func() tea.Msg {
			_, err := m.client.Approve(m.ctx, item.CVEID)
			return doneMsg{flash: "Published " + item.CVEID, err: err}
		})
	}
	if p, ok := pick(m.proposals, m.table.Cursor(), m.tab == tabProposals); ok {
		m.ask("Approve proposal "+p.ID+": "+p.Method+" "+p.Path+"?", func() tea.Msg {
			_, err := m.client.ApproveProposal(m.ctx, p.ID)
			return doneMsg{flash: "Approved proposal " + p.ID, err: err}
		})
	}
}

func (m Model) enter() tea.Cmd {
	if id, ok := pick(m.ids, m.table.Cursor(), m.tab == tabIDs); ok {
		return func() tea.Msg {
			record, err := m.client.Record(m.ctx, id.ID)
			return recordMsg{id.ID, record, err}
		}
	}
	if item, ok := pick(m.review, m.table.Cursor(), m.tab == tabReview); ok {
		return func() tea.Msg { return recordMsg{item.CVEID, item.Record, nil} }
	}
	return nil
}

func (m *Model) ask(question string, answer tea.Cmd) {
	m.question, m.answer = question, answer
}

func (m *Model) load(t tab) tea.Cmd {
	if t != m.tab {
		m.tab = t
		m.layout()
	}
	m.loading = true
	ctx, client := m.ctx, m.client
	return func() tea.Msg {
		var data any
		var err error
		switch t {
		case tabIDs:
			data, err = client.ListIDs(ctx, "")
		case tabReview:
			data, err = client.Review(ctx)
		case tabProposals:
			data, err = client.Proposals(ctx)
		case tabAudit:
			data, err = client.Audit(ctx, cveservices.AuditFilter{})
		}
		return loadedMsg{t, data, err}
	}
}

func (m *Model) show(data any) {
	var rows []table.Row
	switch data := data.(type) {
	case []cveservices.CVEID:
		m.ids = data
		for _, id := range data {
			state := render.State(id.State)
			if id.Cvedexd != nil {
				state += render.Faint.Render(" " + id.Cvedexd.State)
			}
			rows = append(rows, table.Row{id.ID, state, id.Reserved.Format("2006-01-02"), id.RequestedBy.User})
		}
	case []cveservices.ReviewItem:
		m.review = data
		for _, item := range data {
			var r struct {
				CNA struct {
					Title string `json:"title"`
				} `json:"cnaContainer"`
			}
			_ = json.Unmarshal(item.Record, &r)
			rows = append(rows, table.Row{item.CVEID, item.Submitter, day(item.UpdatedAt), r.CNA.Title})
		}
	case []cveservices.Proposal:
		m.proposals = data
		for _, p := range data {
			rows = append(rows, table.Row{p.ID, p.Method + " " + p.Path, day(p.CreatedAt)})
		}
	case []cveservices.AuditEntry:
		m.audit = data
		for _, e := range data {
			status := strconv.Itoa(e.Status)
			if e.Status >= 400 {
				status = render.Bad.Render(status)
			}
			rows = append(rows, table.Row{strings.Replace(e.Time[:min(len(e.Time), 19)], "T", " ", 1),
				deref(e.Actor), deref(e.ActorKind), e.Method + " " + e.Path, status})
		}
	}
	m.table.SetRows(rows)
	m.table.SetCursor(min(m.table.Cursor(), max(len(rows)-1, 0)))
}

func (m *Model) open(id string, record json.RawMessage) {
	m.reading = id
	m.reader.SetContent(render.Record(record, m.width-4))
	m.reader.GotoTop()
	m.layout()
}

// columns lists each tab's column titles and widths; a width of 0 takes the space left.
var columns = map[tab][]table.Column{
	tabIDs: {
		{Title: "CVE ID", Width: 16},
		{Title: "STATE", Width: 20},
		{Title: "RESERVED", Width: 12},
		{Title: "BY"},
	},
	tabReview: {
		{Title: "CVE ID", Width: 16},
		{Title: "SUBMITTER", Width: 20},
		{Title: "SENT", Width: 12},
		{Title: "TITLE"},
	},
	tabProposals: {{Title: "ID", Width: 38}, {Title: "REQUEST"}, {Title: "CREATED", Width: 12}},
	tabAudit: {{Title: "TIME", Width: 20}, {Title: "ACTOR", Width: 24}, {Title: "AS", Width: 10}, {Title: "REQUEST"},
		{Title: "STATUS", Width: 6}},
}

func (m *Model) layout() {
	body := max(m.height-4, 3)
	cols := append([]table.Column(nil), columns[m.tab]...)
	used := 0
	for _, c := range cols {
		used += c.Width + 2
	}
	for i := range cols {
		if cols[i].Width == 0 {
			cols[i].Width = max(m.width-used-2, 10)
		}
	}
	m.table.SetRows(nil)
	m.table.SetColumns(cols)
	m.table.SetWidth(m.width)
	m.table.SetHeight(body)
	m.reader.SetWidth(m.width)
	m.reader.SetHeight(body)
	m.show(m.current())
}

func (m Model) current() any {
	switch m.tab {
	case tabIDs:
		return m.ids
	case tabReview:
		return m.review
	case tabProposals:
		return m.proposals
	}
	return m.audit
}

func (m Model) position() int {
	for i, t := range m.tabs {
		if t == m.tab {
			return i
		}
	}
	return 0
}

// View draws the interface.
func (m Model) View() tea.View {
	var tabs []string
	for i, t := range m.tabs {
		name := tabNames[t]
		if len(m.tabs) > 1 {
			name = fmt.Sprintf("%d %s", i+1, name)
		}
		if t == m.tab {
			tabs = append(tabs, render.Bold.Reverse(true).Padding(0, 1).Render(name))
		} else {
			tabs = append(tabs, render.Faint.Padding(0, 1).Render(name))
		}
	}
	left := render.Bold.Render(" cvedex ") + " " + strings.Join(tabs, " ")
	creds := m.client.Credentials
	right := render.Faint.Render(strings.TrimPrefix(creds.URL, "https://") + " · " + creds.User + " ")
	header := left + strings.Repeat(" ", max(m.width-lipgloss.Width(left)-lipgloss.Width(right), 1)) + right

	status := []string{""}
	var apiErr *cveservices.Error
	switch {
	case m.question != "":
		status[0] = render.Warn.Render(m.question) + render.Faint.Render(" y/n")
	case m.err != nil:
		status[0] = render.Bad.Render(m.err.Error())
		if errors.As(m.err, &apiErr) {
			details := render.ErrorDetails(apiErr.Details)
			if len(details) > maxDetails {
				details = append(details[:maxDetails], render.Faint.Render(fmt.Sprintf("and %d more", len(details)-maxDetails)))
			}
			for _, detail := range details {
				status = append(status, "  "+detail)
			}
		}
	case m.loading:
		status[0] = m.spinner.View() + render.Faint.Render(" Loading")
	case m.flash != "":
		status[0] = render.Good.Render(m.flash)
	case m.reading == "" && len(m.table.Rows()) == 0:
		status[0] = render.Faint.Render("Nothing here yet.")
	}

	height := max(m.height-4-(len(status)-1), 3)
	hints := "↑↓ move · enter open · r refresh · q quit"
	var body string
	switch {
	case m.reading != "":
		reader := m.reader
		reader.SetHeight(height)
		body = reader.View()
		hints = "↑↓ scroll · esc back · q quit"
		if m.tab == tabIDs {
			hints = "↑↓ scroll · e edit · esc back · q quit"
		}
	case m.tab == tabIDs:
		hints = "↑↓ move · enter open · e edit · n new ID · r refresh · q quit"
	case m.tab == tabReview:
		hints = "↑↓ move · enter read · a approve · r refresh · q quit"
	case m.tab == tabProposals:
		hints = "↑↓ move · a approve · d deny · r refresh · q quit"
	}
	if body == "" {
		table := m.table
		table.SetHeight(height)
		body = table.View()
	}

	if len(m.tabs) > 1 && m.reading == "" {
		hints = strings.Replace(hints, " · r refresh", " · tab switch · r refresh", 1)
	}
	lines := append([]string{header, "", body}, status...)
	lines = append(lines, render.Faint.Render(hints))
	for i := 3; i < len(lines); i++ {
		lines[i] = " " + lines[i]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.WindowTitle = "cvedex"
	return v
}

// pick returns the item under the cursor when the tab shows that kind of item.
func pick[T any](items []T, cursor int, shown bool) (T, bool) {
	var zero T
	if !shown || cursor < 0 || cursor >= len(items) {
		return zero, false
	}
	return items[cursor], true
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
