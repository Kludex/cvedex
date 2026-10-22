package render

import (
	"encoding/json"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// Record renders a CVE JSON 5.x record as a summary wrapped to width. raw may also be a bare CNA
// container, or one wrapped as {"cnaContainer": ...}. Fields that are missing or
// malformed are left out rather than failing: records in the wild do not always match the schema.
func Record(raw json.RawMessage, width int) string {
	var r struct {
		Metadata struct {
			ID            string `json:"cveId"`
			State         string `json:"state"`
			Assigner      string `json:"assignerShortName"`
			DateReserved  string `json:"dateReserved"`
			DatePublished string `json:"datePublished"`
			DateUpdated   string `json:"dateUpdated"`
			DateRejected  string `json:"dateRejected"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA json.RawMessage `json:"cna"`
		} `json:"containers"`
		CNAContainer json.RawMessage `json:"cnaContainer"`
	}
	_ = json.Unmarshal(raw, &r)
	cna := r.Containers.CNA
	switch {
	case r.CNAContainer != nil:
		cna = r.CNAContainer
	case cna == nil:
		cna = raw
	}
	var c struct {
		Title           string          `json:"title"`
		Descriptions    json.RawMessage `json:"descriptions"`
		RejectedReasons json.RawMessage `json:"rejectedReasons"`
		Affected        json.RawMessage `json:"affected"`
		ProblemTypes    json.RawMessage `json:"problemTypes"`
		Metrics         json.RawMessage `json:"metrics"`
		References      json.RawMessage `json:"references"`
	}
	_ = json.Unmarshal(cna, &c)

	var b strings.Builder
	m := r.Metadata
	if m.ID != "" {
		b.WriteString(Bold.Render(m.ID) + "  " + State(m.State) + "\n")
	}
	if c.Title != "" {
		b.WriteString(Bold.Width(width).Render(c.Title) + "\n")
	}
	b.WriteString("\n")
	field := func(label, value string) {
		if value != "" {
			b.WriteString(Label.Render(label) + value + "\n")
		}
	}
	field("Assigner", m.Assigner)
	field("Reserved", day(m.DateReserved))
	field("Published", day(m.DatePublished))
	field("Updated", day(m.DateUpdated))
	field("Rejected", day(m.DateRejected))
	field("Severity", severity(c.Metrics))
	for _, cwe := range weaknesses(c.ProblemTypes) {
		field("Weakness", cwe)
	}
	for _, text := range english(c.Descriptions, "value") {
		b.WriteString("\n" + lipgloss.NewStyle().Width(width).Render(text) + "\n")
	}
	for _, text := range english(c.RejectedReasons, "value") {
		b.WriteString("\n" + Bad.Width(width).Render(text) + "\n")
	}
	if products := affected(c.Affected); len(products) > 0 {
		b.WriteString("\n" + Faint.Render("Affected") + "\n")
		for _, p := range products {
			b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Width(width).Render(p) + "\n")
		}
	}
	var refs []struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(c.References, &refs)
	if len(refs) > 0 {
		b.WriteString("\n" + Faint.Render("References") + "\n")
		for _, ref := range refs {
			b.WriteString("  " + Accent.Render(ref.URL) + "\n")
		}
	}
	return trimLines(strings.TrimRight(b.String(), "\n"))
}

func day(timestamp string) string {
	day, _, _ := strings.Cut(timestamp, "T")
	return day
}

func severity(metrics json.RawMessage) string {
	var list []map[string]json.RawMessage
	_ = json.Unmarshal(metrics, &list)
	for _, metric := range list {
		for _, key := range []string{"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"} {
			var cvss struct {
				Score    float64 `json:"baseScore"`
				Severity string  `json:"baseSeverity"`
				Vector   string  `json:"vectorString"`
			}
			if json.Unmarshal(metric[key], &cvss) == nil && cvss.Vector != "" {
				return fmt.Sprintf("%s %s  %s", severityStyle(cvss.Severity).Render(fmt.Sprintf("%.1f", cvss.Score)),
					severityStyle(cvss.Severity).Render(cvss.Severity), Faint.Render(cvss.Vector))
			}
		}
	}
	return ""
}

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL", "HIGH":
		return Bad
	case "MEDIUM":
		return Warn
	}
	return lipgloss.NewStyle()
}

func weaknesses(problemTypes json.RawMessage) []string {
	var types []struct {
		Descriptions json.RawMessage `json:"descriptions"`
	}
	_ = json.Unmarshal(problemTypes, &types)
	var out []string
	for _, t := range types {
		out = append(out, english(t.Descriptions, "description")...)
	}
	return out
}

// english returns the `key` field of each entry in English, or of every entry when none is.
func english(raw json.RawMessage, key string) []string {
	var entries []map[string]any
	_ = json.Unmarshal(raw, &entries)
	var all, en []string
	for _, e := range entries {
		text, _ := e[key].(string)
		if text == "" {
			continue
		}
		all = append(all, text)
		if lang, _ := e["lang"].(string); strings.HasPrefix(lang, "en") {
			en = append(en, text)
		}
	}
	if len(en) > 0 {
		return en
	}
	return all
}

func affected(raw json.RawMessage) []string {
	var products []struct {
		Vendor   string `json:"vendor"`
		Product  string `json:"product"`
		Versions []struct {
			Version         string `json:"version"`
			Status          string `json:"status"`
			LessThan        string `json:"lessThan"`
			LessThanOrEqual string `json:"lessThanOrEqual"`
		} `json:"versions"`
	}
	_ = json.Unmarshal(raw, &products)
	var out []string
	for _, p := range products {
		var ranges []string
		for _, v := range p.Versions {
			r := v.Version
			switch {
			case v.LessThan != "":
				r = fmt.Sprintf("%s to before %s", v.Version, v.LessThan)
			case v.LessThanOrEqual != "":
				r = fmt.Sprintf("%s to %s", v.Version, v.LessThanOrEqual)
			}
			if v.Status != "affected" {
				r += " (" + v.Status + ")"
			}
			ranges = append(ranges, r)
		}
		line := Bold.Render(strings.TrimSpace(p.Vendor + " " + p.Product))
		if len(ranges) > 0 {
			line += "  " + strings.Join(ranges, ", ")
		}
		out = append(out, line)
	}
	return out
}
