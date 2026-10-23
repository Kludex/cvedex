package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/aymanbagabas/go-udiff"
)

// Clean makes text from CVE Services safe to print: control characters, which could move the
// cursor, hide text or set the clipboard, and bidirectional overrides, which reorder what is
// shown, become visible escapes such as \x1b. Newlines and tabs are kept.
func Clean(s string) string {
	if strings.IndexFunc(s, unsafe) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafe(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func unsafe(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case unicode.IsControl(r):
		return true
	}
	return unicode.Is(unicode.Bidi_Control, r)
}

// JSON renders raw as indented JSON, cleaned. It shows every field of a record, including those
// Record leaves out.
func JSON(raw json.RawMessage) string {
	var out bytes.Buffer
	if json.Indent(&out, raw, "", "  ") != nil {
		return Clean(string(raw))
	}
	return Clean(out.String())
}

// Diff renders the changes from one JSON document to another as a colored unified diff, or ""
// when they are the same.
func Diff(fromLabel string, from json.RawMessage, toLabel string, to json.RawMessage) string {
	unified := udiff.Unified(fromLabel, toLabel, JSON(from)+"\n", JSON(to)+"\n")
	lines := strings.Split(strings.TrimRight(unified, "\n"), "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
			lines[i] = Bold.Render(line)
		case strings.HasPrefix(line, "+"):
			lines[i] = Good.Render(line)
		case strings.HasPrefix(line, "-"):
			lines[i] = Bad.Render(line)
		case strings.HasPrefix(line, "@@"):
			lines[i] = Accent.Render(line)
		}
	}
	return strings.Join(lines, "\n")
}

// cleanJSON returns raw with every string in it cleaned.
func cleanJSON(raw json.RawMessage) json.RawMessage {
	var doc any
	_ = json.Unmarshal(raw, &doc)
	out, _ := json.Marshal(cleanValue(doc)) // decoded JSON always encodes
	return out
}

func cleanValue(v any) any {
	switch v := v.(type) {
	case string:
		return Clean(v)
	case []any:
		for i := range v {
			v[i] = cleanValue(v[i])
		}
	case map[string]any:
		for k := range v {
			v[k] = cleanValue(v[k])
		}
	}
	return v
}
