package tui_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	s.shows("CVE IDs", "CVE-2026-1100", "PUBLISHED", "alice@acme.test", "127.0.0.1", "n new ID")
	s.hides("1 CVE IDs")
	s.hides("tab switch")
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

	s.press("2", "a", "d", "tab", "r")
	s.shows("CVE IDs", "Unauthorized (UNAUTHORIZED)")
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
		Response: `{"cves":[{"cve_id":"CVE-2026-1100","action":"publish","revision":2,` +
			`"submitter":"bob","updated_at":"2026-10-22T10:00:00Z","previous":{"cnaContainer":{"title":"Traversal"}},` +
			`"record":{"cnaContainer":{"title":"Path traversal in widget"}}},` +
			`{"cve_id":"CVE-2026-1101","action":"reject","revision":1,"submitter":"bob\u001b[2J",` +
			`"record":{"cnaContainer":{"rejectedReasons":[{"lang":"en","value":"Unused."}]}}}]}`,
	}
	proposals := cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[` +
		`{"id":"p1","method":"POST","path":"/api/cve-id?amount=1","body":"{\"x\":1}",` +
		`"created_at":"2026-10-22T10:00:00Z"}]}`}
	s := start(
		t,
		health,
		review,
		proposals,
		cassette.Exchange{
			Method: "GET",
			Path:   "/api/cve-id",
			Response: `{"cve_ids":[{"cve_id":"CVE-2026-1100","state":"RESERVED",` +
				`"cvedexd":{"state":"in_review"}}]}`,
		},
		review,
		cassette.Exchange{Method: "POST", Path: "/api/cvedexd/cve/CVE-2026-1100/approve", Body: `{"revision":2}`,
			Response: `{"created":{}}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Response: `{"cves":[]}`},
		proposals,
		cassette.Exchange{
			Method:   "POST",
			Path:     "/api/cvedexd/proposals/p1/approve",
			Status:   502,
			Response: `{"error":"UPSTREAM","message":"CVE Services is down"}`,
		},
		cassette.Exchange{
			Method:   "POST",
			Path:     "/api/cvedexd/proposals/p1/deny",
			Response: `{"id":"p1","status":"denied"}`,
		},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/audit", Response: `{"audit":[` +
			`{"id":1,"ts":"2026-10-22T10:00:00.000Z","actor":"bob","actor_kind":"agent",` +
			`"method":"POST","path":"/api/cve-id","status":202},` +
			`{"id":2,"ts":"2026-10-22T10:01:00.000Z","actor":"bob","actor_kind":"user",` +
			`"method":"GET","path":"/api/cve-id","status":null}],"next":null}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
	)
	s.shows("1 CVE IDs", "2 Review", "3 Proposals", "4 Audit", "RESERVED in_review", "tab switch")

	s.press("tab")
	s.shows("CVE-2026-1100", "publish", "bob", "Path traversal in widget", "a approve", `bob\x1b[2J`)
	s.press("down", "a")
	s.shows("Reject CVE-2026-1101, revision 1, with your key? It will be public. y/n")
	s.press("n", "up", "enter")
	s.shows("revision 2 from bob, asking to publish", "Changes since the revision before", "a approve", "esc back")
	s.press("a")
	s.shows("Publish CVE-2026-1100, revision 2, with your key? It will be public. y/n")
	s.press("y")
	s.shows("Published CVE-2026-1100", "enter read")

	s.press("tab")
	s.shows("p1", "POST /api/cve-id?amount=1", "d deny")
	s.press("enter")
	s.shows("POST /api/cve-id?amount=1  proposed 2026-10-22", `"x": 1`, "d deny")
	s.press("a", "y")
	s.shows("CVE Services is down (UPSTREAM)", `"x": 1`)
	s.press("d", "y")
	s.shows("Denied proposal p1", "enter read")

	s.press("4")
	s.shows("2026-10-22 10:00:00", "agent", "202", "?")
	s.press("down", "shift+tab")
	s.shows("Proposals")
}

func TestCvedexdSubmitter(t *testing.T) {
	s := start(t,
		cassette.Exchange{Method: "GET", Path: "/api/health-check", Response: `{"server":"cvedexd","version":"0.1.0"}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/review", Status: 403,
			Response: `{"error":"NOT_ALLOWED","message":"Only CNA users can do this"}`},
		cassette.Exchange{Method: "GET", Path: "/api/cvedexd/proposals", Response: `{"proposals":[]}`},
		cassette.Exchange{Method: "GET", Path: "/api/cve-id",
			Response: `{"cve_ids":[{"cve_id":"CVE-2026-1102","state":"RESERVED",` +
				`"cvedexd":{"state":"reserved","note":"Add a CWE."}},` +
				`{"cve_id":"CVE-2026-1103","state":"RESERVED","cvedexd":{"state":"in_review"}}]}`},
	)
	s.shows("1 CVE IDs", "2 Proposals", "tab switch", "RESERVED changes requested",
		"Changes requested: Add a CWE.")
	s.press("down")
	s.hides("Changes requested:")
	s.hides("Review")
	s.hides("Audit")
}

// TestMain lets the test binary act as $EDITOR: it saves the path and content it was given to
// $CVEDEX_TEST_EDITOR_SAW, then writes $CVEDEX_TEST_EDITOR over the file unless it is empty, or
// deletes the file if it is "<delete>".
func TestMain(m *testing.M) {
	content, ok := os.LookupEnv("CVEDEX_TEST_EDITOR")
	if !ok {
		os.Exit(m.Run())
	}
	path := os.Args[len(os.Args)-1]
	original, err := os.ReadFile(path)
	if err == nil {
		err = os.WriteFile(os.Getenv("CVEDEX_TEST_EDITOR_SAW"), []byte(path+"\n"+string(original)), 0o600)
	}
	switch {
	case err != nil:
	case content == "<delete>":
		err = os.Remove(path)
	case content != "":
		err = os.WriteFile(path, []byte(content), 0o600)
	}
	if err != nil {
		os.Exit(1)
	}
}

// program runs the interface in a real tea.Program, which editing needs to suspend it.
type program struct {
	t      *testing.T
	p      *tea.Program
	mu     sync.Mutex
	screen string
	saw    string
}

func runProgram(t *testing.T, exchanges ...cassette.Exchange) *program {
	t.Helper()
	url := cassette.Serve(t, exchanges...)
	client := cveservices.New(cveservices.Credentials{URL: url, Org: "acme", User: "alice@acme.test", Key: "key"})
	pr := &program{t: t, saw: filepath.Join(t.TempDir(), "saw")}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", os.Args[0])
	t.Setenv("CVEDEX_TEST_EDITOR_SAW", pr.saw)
	pr.p = tea.NewProgram(tui.New(context.Background(), client),
		tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithWindowSize(120, 20),
		tea.WithFilter(func(m tea.Model, msg tea.Msg) tea.Msg {
			pr.mu.Lock()
			defer pr.mu.Unlock()
			pr.screen = ansi.Strip(m.View().Content)
			return msg
		}))
	done := make(chan struct{})
	go func() {
		_, _ = pr.p.Run()
		close(done)
	}()
	t.Cleanup(func() {
		pr.p.Quit()
		<-done
	})
	return pr
}

func (pr *program) press(k string, code rune) {
	pr.p.Send(tea.KeyPressMsg{Code: code, Text: k})
}

// edit sets what the fake editor writes, then presses e.
func (pr *program) edit(content string) {
	pr.t.Setenv("CVEDEX_TEST_EDITOR", content)
	pr.press("e", 'e')
}

func (pr *program) waitFor(want ...string) {
	pr.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pr.mu.Lock()
		screen := pr.screen
		pr.mu.Unlock()
		missing := slices.IndexFunc(want, func(w string) bool { return !strings.Contains(screen, w) })
		if missing < 0 {
			return
		}
		if time.Now().After(deadline) {
			pr.t.Fatalf("screen never showed %q:\n%s", want[missing], screen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sawEditing returns the path and content the fake editor last opened.
func (pr *program) sawEditing() (string, string) {
	pr.t.Helper()
	data, err := os.ReadFile(pr.saw)
	if err != nil {
		pr.t.Fatal(err)
	}
	path, content, _ := strings.Cut(string(data), "\n")
	return path, content
}

func TestEditReservedID(t *testing.T) {
	publish := cassette.Load(t, "publish")
	var sent struct {
		CNA json.RawMessage `json:"cnaContainer"`
	}
	if err := json.Unmarshal([]byte(publish.Body), &sent); err != nil {
		t.Fatal(err)
	}
	dne := cassette.Load(t, "cve-record-dne")
	dne.Path = "/api/cve/CVE-2026-1101"
	invalid := cassette.Load(t, "bad-request")
	invalid.Path = "/api/cve/CVE-2026-1101/cna"
	publish.Path = "/api/cve/CVE-2026-1101/cna"
	list := cassette.Exchange{Method: "GET", Path: "/api/cve-id",
		Response: `{"cve_ids":[{"cve_id":"CVE-2026-1101","state":"RESERVED"}]}`}
	pr := runProgram(t, cassette.Load(t, "health-check"), list, dne, dne, invalid, publish, list)

	pr.waitFor("CVE-2026-1101", "RESERVED", "e edit")
	pr.press("", tea.KeyEnter)
	pr.waitFor("CVE-2026-1101 has no record yet. Press e to write one.")

	pr.edit("{}")
	pr.waitFor("Publish CVE-2026-1101? It will be public. y/n")
	if _, opened := pr.sawEditing(); !strings.Contains(opened, `"descriptions": [{"lang": "en", "value": ""}]`) {
		t.Errorf("template: %s", opened)
	}
	pr.press("y", 'y')
	pr.waitFor("press e to fix it", "INVALID_JSON_SCHEMA", "/cnaContainer:")
	pr.press("q", 'q')
	pr.waitFor("Quit and discard your unsent drafts? y/n")
	pr.press("n", 'n')

	pr.edit(string(sent.CNA))
	pr.waitFor("Publish CVE-2026-1101?")
	path, opened := pr.sawEditing()
	if opened != "{}" {
		t.Errorf("the draft did not reopen: %s", opened)
	}
	pr.press("y", 'y')
	pr.waitFor("Published CVE-2026-1101")
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("draft %s was not removed: %v", path, err)
	}
}

func TestEditPublishedRecord(t *testing.T) {
	record := cassette.Load(t, "cve-2025-0001")
	record.Path = "/api/cve/CVE-2026-1099"
	list := cassette.Load(t, "cve-id-list")
	inReview := cassette.Exchange{Method: "PUT", Path: "/api/cve/CVE-2026-1099/cna",
		Response: `{"message":"CVE-2026-1099 was submitted for review","state":"in_review"}`}
	pr := runProgram(t, cassette.Load(t, "health-check"), list, record, record, record, inReview, list)

	pr.waitFor("CVE-2026-1099")
	pr.press("", tea.KeyEnter)
	pr.waitFor("References", "e edit")

	pr.edit("")
	pr.waitFor("No changes to CVE-2026-1099")
	_, opened := pr.sawEditing()
	if strings.Contains(opened, "providerMetadata") || !strings.Contains(opened, `"descriptions"`) {
		t.Errorf("container: %s", opened)
	}

	pr.edit("not json")
	pr.waitFor("CVE-2026-1099 is not valid JSON, press e to fix it")
	t.Setenv("VISUAL", "cvedex-no-such-editor")
	pr.edit("")
	pr.waitFor("editor: exec:")
	t.Setenv("VISUAL", "")

	pr.edit(`{"descriptions":[{"lang":"en","value":"Changed."}]}`)
	pr.waitFor("Update CVE-2026-1099? It will be public. y/n")
	pr.press("y", 'y')
	pr.waitFor("Sent for review: CVE-2026-1099", "n new ID")
}

func TestErrorDetails(t *testing.T) {
	record := cassette.Load(t, "cve-2025-0001")
	record.Path = "/api/cve/CVE-2026-1099"
	var details []string
	for i := range 7 {
		details = append(details, fmt.Sprintf(`{"instancePath":"/field%d","message":"is wrong"}`, i))
	}
	s := start(t,
		cassette.Load(t, "health-check"),
		cassette.Load(t, "cve-id-list"),
		cassette.Exchange{Method: "POST",
			Path:   fmt.Sprintf("/api/cve-id?amount=1&cve_year=%d&short_name=acme", time.Now().Year()),
			Status: 400, Response: `{"error":"BAD_INPUT","message":"Bad input","details":{"errors":[` +
				strings.Join(details, ",") + `]}}`},
		record,
	)
	s.press("n", "y")
	s.shows("Bad input (BAD_INPUT)", "/field0: is wrong", "/field4: is wrong", "and 2 more")
	s.hides("/field5")

	s.press("enter", "down")
	s.shows("References", "esc back")
}

func TestEditFailures(t *testing.T) {
	record := func(response string) cassette.Exchange {
		return cassette.Exchange{Method: "GET", Path: "/api/cve/CVE-2026-1099", Response: response}
	}
	down := record(`{"error":"DOWN","message":"Out of service"}`)
	down.Status = 500
	local := record(`{"cnaContainer":{"title":"Local draft"}}`)
	pr := runProgram(t, cassette.Load(t, "health-check"), cassette.Load(t, "cve-id-list"),
		down, record(`[]`), record(`{"containers":{"cna":[]}}`), local, local)

	pr.waitFor("CVE-2026-1099")
	pr.edit("")
	pr.waitFor("Out of service (DOWN)")
	pr.edit("")
	pr.waitFor("cannot unmarshal array into Go value of type struct")
	pr.edit("")
	pr.waitFor("cannot unmarshal array into Go value of type map")

	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, missing)
	}
	pr.edit("")
	pr.waitFor("CVE-2026-1099-")
	tmp := t.TempDir()
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, tmp)
	}

	pr.edit("<delete>")
	pr.waitFor(filepath.Join(tmp, "CVE-2026-1099-"))
	if _, opened := pr.sawEditing(); !strings.Contains(opened, `"title": "Local draft"`) {
		t.Errorf("container: %s", opened)
	}
}

func TestQuitRemovesDrafts(t *testing.T) {
	record := cassette.Load(t, "cve-2025-0001")
	record.Path = "/api/cve/CVE-2026-1099"
	for _, key := range []string{"q", "ctrl+c"} {
		t.Run(key, func(t *testing.T) {
			pr := runProgram(t, cassette.Load(t, "health-check"), cassette.Load(t, "cve-id-list"), record)
			pr.waitFor("CVE-2026-1099")
			pr.edit("not json")
			pr.waitFor("CVE-2026-1099 is not valid JSON")
			path, _ := pr.sawEditing()
			if key == "q" {
				pr.press("q", 'q')
				pr.waitFor("Quit and discard your unsent drafts? y/n")
				pr.press("y", 'y')
			} else {
				pr.p.Send(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
			}
			deadline := time.Now().Add(5 * time.Second)
			for _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist); _, err = os.Stat(path) {
				if time.Now().After(deadline) {
					t.Fatalf("draft %s was not removed: %v", path, err)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
