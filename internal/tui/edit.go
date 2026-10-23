package tui

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/Kludex/cvedex/cveservices"
	"github.com/Kludex/cvedex/internal/record"
)

// template is what `e` opens for a reserved ID: the fields CVE Services requires, a title and a CWE.
const template = `{
  "title": "",
  "descriptions": [{"lang": "en", "value": ""}],
  "affected": [
    {
      "vendor": "",
      "product": "",
      "versions": [{"version": "0", "lessThan": "", "status": "affected", "versionType": "semver"}]
    }
  ],
  "problemTypes": [{"descriptions": [{"lang": "en", "type": "CWE", "cweId": "CWE-", "description": ""}]}],
  "references": [{"url": ""}]
}
`

// draft is a CNA container being edited in a temporary file. It is kept until it is sent, so a
// rejected draft reopens with the user's changes.
type draft struct {
	id       string
	path     string
	original []byte
	publish  bool
}

type (
	draftMsg struct {
		draft draft
		err   error
	}
	editedMsg struct {
		draft draft
		err   error
	}
)

// edit opens id's draft if it has one, else its CNA container, else the template.
func (m Model) edit(id string) tea.Cmd {
	if d, ok := m.drafts[id]; ok {
		return openEditor(d)
	}
	return func() tea.Msg {
		d := draft{id: id}
		record, err := m.client.Record(m.ctx, id)
		switch {
		case noRecord(err):
			d.publish, d.original = true, []byte(template)
		case err != nil:
			return draftMsg{err: err}
		default:
			if d.original, err = container(record); err != nil {
				return draftMsg{err: err}
			}
		}
		return writeDraft(d, d.original)
	}
}

// fromAdvisory starts a draft for id from a GitHub repository advisory.
func (m Model) fromAdvisory(id cveservices.CVEID, url string) tea.Cmd {
	return func() tea.Msg {
		cna, err := record.FromAdvisory(m.ctx, url)
		if err != nil {
			return draftMsg{err: err}
		}
		return writeDraft(draft{id: id.ID, original: []byte(template), publish: id.State == cveservices.StateReserved}, cna)
	}
}

func writeDraft(d draft, content []byte) draftMsg {
	f, err := os.CreateTemp("", d.id+"-*.json")
	if err != nil {
		return draftMsg{err: err}
	}
	d.path = f.Name()
	_, err = f.Write(content)
	return draftMsg{d, errors.Join(err, f.Close())}
}

// openEditor suspends the interface and runs $VISUAL or $EDITOR on the draft.
func openEditor(d draft) tea.Cmd {
	args := strings.Fields(cmp.Or(os.Getenv("VISUAL"), os.Getenv("EDITOR"), "vi"))
	editor := exec.Command(args[0], append(args[1:], d.path)...)
	return tea.ExecProcess(editor, func(err error) tea.Msg { return editedMsg{d, err} })
}

// edited asks to send the draft once the editor closes, unless it is unchanged or not JSON.
func (m *Model) edited(msg editedMsg) {
	d := msg.draft
	data, err := os.ReadFile(d.path)
	switch {
	case msg.err != nil:
		m.err = fmt.Errorf("editor: %w", msg.err)
		return
	case err != nil:
		m.err = err
		return
	case bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(d.original)):
		m.discard(d.id)
		m.flash = "No changes to " + d.id
		return
	case !json.Valid(data):
		m.err = fmt.Errorf("%s is not valid JSON, press e to fix it", d.id)
		return
	}
	if err := record.Check(data); err != nil {
		m.err = fmt.Errorf("%s is %w, press e to fix it", d.id, err)
		return
	}
	verb, done, send := "Update", "Updated", m.client.Update
	if d.publish {
		verb, done, send = "Publish", "Published", m.client.Publish
	}
	m.ask(verb+" "+d.id+"? It will be public.", func() tea.Msg {
		written, err := send(m.ctx, d.id, data)
		if err != nil {
			return doneMsg{err: fmt.Errorf("%w, press e to fix it", err)}
		}
		if cveservices.InReview(written) {
			done = "Sent for review:"
		}
		return doneMsg{flash: done + " " + d.id, saved: d.id}
	})
}

// quit removes the drafts left unsent, which may hold embargoed details, then quits.
func (m Model) quit() tea.Cmd {
	var paths []string
	for _, d := range m.drafts {
		paths = append(paths, d.path)
	}
	return func() tea.Msg {
		for _, path := range paths {
			_ = os.Remove(path)
		}
		return tea.QuitMsg{}
	}
}

func (m *Model) discard(id string) {
	if d, ok := m.drafts[id]; ok {
		_ = os.Remove(d.path)
		delete(m.drafts, id)
	}
}

// container returns the CNA container of a record, indented, without the providerMetadata that
// CVE Services fills in itself.
func container(record json.RawMessage) ([]byte, error) {
	var r struct {
		Containers struct {
			CNA json.RawMessage `json:"cna"`
		} `json:"containers"`
		CNAContainer json.RawMessage `json:"cnaContainer"`
	}
	if err := json.Unmarshal(record, &r); err != nil {
		return nil, err
	}
	cna := r.Containers.CNA
	if r.CNAContainer != nil {
		cna = r.CNAContainer
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(cna, &fields); err != nil {
		return nil, err
	}
	delete(fields, "providerMetadata")
	data, err := json.MarshalIndent(fields, "", "  ")
	return append(data, '\n'), err
}

func noRecord(err error) bool {
	var apiErr *cveservices.Error
	return errors.As(err, &apiErr) && apiErr.Code == "CVE_RECORD_DNE"
}
