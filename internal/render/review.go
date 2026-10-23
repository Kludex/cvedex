package render

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Kludex/cvedex/cveservices"
)

// Review renders a record in review: what the submitter asks for, a summary, the changes from
// the revision before or the published record, and the full record, so nothing hides from the
// reviewer.
func Review(item cveservices.ReviewItem, width int) string {
	parts := []string{
		Bold.Render(item.CVEID) + Faint.Render(fmt.Sprintf("  revision %d from %s, asking to %s",
			item.Revision, Clean(item.Submitter), Clean(item.Action))),
		Record(item.Record, width),
	}
	switch {
	case exists(item.Previous):
		parts = append(parts, Bold.Render("Changes since the revision before"),
			Diff("before", item.Previous, "now", item.Record))
	case exists(item.Published):
		parts = append(parts, Bold.Render("Changes from the published record"),
			Diff("published", item.Published, "now", item.Record))
	}
	return strings.Join(append(parts, Bold.Render("Full record"), JSON(item.Record)), "\n\n")
}

func exists(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// Proposal renders a proposal as the request it sends.
func Proposal(p cveservices.Proposal) string {
	text := Bold.Render(Clean(p.Method+" "+p.Path)) + Faint.Render("  proposed "+day(p.CreatedAt))
	if p.Body != nil {
		text += "\n\n" + JSON(json.RawMessage(*p.Body))
	}
	return text
}
