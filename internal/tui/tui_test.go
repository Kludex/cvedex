package tui_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/cassette"
	"github.com/Kludex/cvedex/internal/tui"
)

// session drives the interface the way a tea.Program would, running commands to completion.
type session struct {
	t      *testing.T
	model  tea.Model
	quit   bool
	height int
}

func start(t *testing.T, exchanges ...cassette.Exchange) *session {
	t.Helper()
	client := cveservices.New(
		cveservices.Credentials{URL: cassette.Serve(t, exchanges...), Org: "acme", User: "alice@acme.test", Key: "key"},
	)
	s := &session{t: t, model: tui.New(context.Background(), client)}
	s.send(tea.WindowSizeMsg{Width: 120, Height: 20})
	s.run(s.model.Init())
	return s
}

func (s *session) send(msg tea.Msg) {
	if size, ok := msg.(tea.WindowSizeMsg); ok {
		s.height = size.Height
	}
	var cmd tea.Cmd
	s.model, cmd = s.model.Update(msg)
	s.run(cmd)
}

func (s *session) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, c := range msg {
			s.run(c)
		}
	case tea.QuitMsg:
		s.quit = true
	case spinner.TickMsg:
		s.model, _ = s.model.Update(msg)
	default:
		s.send(msg)
	}
}

func (s *session) press(keys ...string) {
	for _, k := range keys {
		named := map[string]rune{"enter": tea.KeyEnter, "tab": tea.KeyTab, "esc": tea.KeyEscape, "down": tea.KeyDown}
		if k == "shift+tab" {
			s.send(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
		} else if code, ok := named[k]; ok {
			s.send(tea.KeyPressMsg{Code: code})
		} else {
			s.send(tea.KeyPressMsg{Code: rune(k[0]), Text: k})
		}
	}
}

func (s *session) shows(want ...string) {
	s.t.Helper()
	screen := ansi.Strip(s.model.View().Content)
	if lines := strings.Count(screen, "\n") + 1; lines > s.height {
		s.t.Errorf("screen has %d lines, window %d", lines, s.height)
	}
	for _, w := range want {
		if !strings.Contains(screen, w) {
			s.t.Errorf("screen lacks %q:\n%s", w, screen)
		}
	}
}

func (s *session) hides(text string) {
	s.t.Helper()
	if screen := ansi.Strip(s.model.View().Content); strings.Contains(screen, text) {
		s.t.Errorf("screen shows %q:\n%s", text, screen)
	}
}

func TestCVEServices(t *testing.T) {
	record := cassette.Load(t, "cve-2025-0001")
	record.Path = "/api/cve/CVE-2026-1100"
	year := time.Now().Year()
	s := start(
		t,
		cassette.Load(t, "health-check"),
		cassette.Load(t, "cve-id-list"),
		record,
		cassette.Exchange{Method: "POST", Path: fmt.Sprintf("/api/cve-id?amount=1&cve_year=%d&short_name=acme", year),
			Response: `{"cve_ids":[{"cve_id":"CVE-2026-1101","state":"RESERVED"}]}`},
		cassette.Load(t, "cve-id-list"),
		cassette.Exchange{
			Method:   "GET",
			Path:     "/api/cve-id",
			Status:   401,
			Response: `{"error":"UNAUTHORIZED","message":"Unauthorized"}`,
		},
	)
	s.shows("1 CVE IDs", "CVE-2026-1100", "PUBLISHED", "alice@acme.test", "127.0.0.1", "n new ID")
	s.hides("Review")

	s.press("down", "enter")
	s.shows("CVE-2025-0001", "References", "esc back")
	s.press("esc")
	s.shows("CVE-2026-1099")

	s.press("n")
	s.shows(fmt.Sprintf("Reserve a CVE ID for %d? y/n", year))
	s.press("x")
	s.hides("Reserve a CVE ID")
	s.press("n", "y")
	s.shows("Reserved CVE-2026-1101")

	s.press("2", "a", "d", "tab")
	s.shows("1 CVE IDs", "Unauthorized (UNAUTHORIZED)")
	s.send(tea.WindowSizeMsg{Width: 80, Height: 10})
	s.shows("CVE-2026-1100")

	s.press("q")
	if !s.quit {
		t.Error("q did not quit")
	}
}

func TestCvedexd(t *testing.T) {
	health := cassette.Exchange{
		Method:   "GET",
		Path:     "/api/health-check",
		Response: `{"server":"cvedexd","version":"0.1.0"}`,
	}
	review := cassette.Exchange{
		Method: "GET",
		Path:   "/api/cvedexd/review",
		Response: `{"cves":[{"cve_id":"CVE-2026-1100",` +
			`"submitter":"bob","updated_at":"2026-10-22T10:00:00Z",` +
			`"record":{"cnaContainer":{"title":"Path traversal in widget"}}}]}`,
	}
	proposals := cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
		`{"id":"p1","method":"POST","path":"/api/cve-id?amount=1","body":null,"created_at":"2026-10-22T10:00:00Z"}]}`}
	s := start(
		t,
		health,
		cassette.Exchange{
			Method: "GET",
			Path:   "/api/cve-id",
			Response: `{"cve_ids":[{"cve_id":"CVE-2026-1100","state":"RESERVED",` +
				`"cvedexd":{"state":"in_review"}}]}`,
		},
		review,
		cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/approve", Response: `{"created":{}}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: `{"cves":[]}`},
		proposals,
		cassette.Exchange{
			Method:   "POST",
			Path:     "/api/cvedexd/proposals/p1/approve",
			Status:   502,
			Response: `{"error":"UPSTREAM","message":"CVE Services is down"}`,
		},
		proposals,
		cassette.Exchange{
			Method:   "POST",
			Path:     "/api/cvedexd/proposals/p1/deny",
			Response: `{"id":"p1","status":"denied"}`,
		},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/audit", Response: `{"audit":[` +
			`{"id":1,"ts":"2026-10-22T10:00:00.000Z","actor":"bob","actor_kind":"agent",` +
			`"method":"POST","path":"/api/cve-id","status":202},` +
			`{"id":2,"ts":"2026-10-22T10:01:00.000Z","actor":null,"actor_kind":null,` +
			`"method":"GET","path":"/api/cve-id","status":401}]}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
	)
	s.shows("1 CVE IDs", "2 Review", "3 Proposals", "4 Audit", "RESERVED in_review")

	s.press("tab")
	s.shows("CVE-2026-1100", "bob", "Path traversal in widget", "a approve")
	s.press("enter")
	s.shows("Path traversal in widget", "esc back")
	s.press("h", "a")
	s.shows("Publish CVE-2026-1100 with your key? It will be public. y/n")
	s.press("y")
	s.shows("Published CVE-2026-1100")

	s.press("tab")
	s.shows("p1", "POST /api/cve-id?amount=1", "d deny")
	s.press("a", "y")
	s.shows("CVE Services is down (UPSTREAM)")
	s.press("d", "y")
	s.shows("Denied proposal p1")

	s.press("4")
	s.shows("2026-10-22 10:00:00", "agent", "401")
	s.press("down", "shift+tab")
	s.shows("Proposals")
}
