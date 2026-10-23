// Package record builds and checks CNA containers, the part of a CVE JSON 5 record a CNA writes.
package record

import (
	"bytes"
	_ "embed"
	"errors"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// schemaJSON is CVE_Record_Format_bundled_cnaPublishedContainer.json from CVEProject/cve-schema v5.2.0.
//
//go:embed schema.json
var schemaJSON []byte

var schema = sync.OnceValue(func() *jsonschema.Schema {
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON)) // embedded, so always JSON
	c := jsonschema.NewCompiler()
	_ = c.AddResource("cna.json", doc) // the compiler is empty, so the URL is free
	return c.MustCompile("cna.json")
})

var printer = message.NewPrinter(language.English)

// InvalidError lists how a CNA container breaks the CVE JSON 5 schema.
type InvalidError struct {
	Problems []string
}

func (e *InvalidError) Error() string {
	return "not a valid CNA container"
}

// Check validates a CNA container against the CVE JSON 5 schema, as CVE Services will. Without
// providerMetadata, which CVE Services fills in, it checks the rest.
func Check(cna []byte) error {
	container, _ := jsonschema.UnmarshalJSON(bytes.NewReader(cna))
	fields, ok := container.(map[string]any)
	if !ok {
		return &InvalidError{Problems: []string{"- it is not a JSON object"}}
	}
	if _, ok := fields["providerMetadata"]; !ok {
		fields["providerMetadata"] = map[string]any{"orgId": "00000000-0000-4000-8000-000000000000"}
	}
	var invalid *jsonschema.ValidationError
	if !errors.As(schema().Validate(map[string]any{"cnaContainer": fields}), &invalid) {
		return nil
	}
	return &InvalidError{Problems: problems(invalid, "/", 0, nil)}
}

// problems flattens the validator's tree into indented lines, skipping its "validation failed"
// levels and a location already given by the line above.
func problems(e *jsonschema.ValidationError, parent string, depth int, lines []string) []string {
	switch e.ErrorKind.(type) {
	case *kind.Schema, *kind.Group, *kind.Reference:
	default:
		at := "/" + strings.Join(e.InstanceLocation[1:], "/")
		text := e.ErrorKind.LocalizedString(printer)
		if at != parent {
			text = at + ": " + text
		}
		line := strings.Repeat("  ", depth) + "- " + text
		if len(lines) == 0 || lines[len(lines)-1] != line {
			lines = append(lines, line)
		}
		parent, depth = at, depth+1
	}
	for _, cause := range e.Causes {
		lines = problems(cause, parent, depth, lines)
	}
	return lines
}
