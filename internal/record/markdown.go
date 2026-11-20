package record

import (
	"fmt"
	"strings"

	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	east "github.com/yuin/goldmark/v2/extension/ast"
	"github.com/yuin/goldmark/v2/parser"
	"github.com/yuin/goldmark/v2/renderer/html"
)

// describe turns an advisory's GitHub Markdown into a description. Its value is plain text, which
// is what cve.org and most tools show, and a supportingMedia entry holds the same as HTML. Raw HTML
// in the Markdown is left out of both.
func describe(markdown string) text {
	source := []byte(strings.ReplaceAll(markdown, "\r\n", "\n"))
	doc := parser.New(parser.WithExtensions(
		extension.NewLinkifyParser(), extension.NewTableParser(), extension.NewStrikethroughParser(),
	)).Parse(source)
	var rendered strings.Builder
	// A strings.Builder never fails to write.
	_ = html.New(html.WithExtensions(
		extension.NewTableHTMLRenderer(), extension.NewStrikethroughHTMLRenderer(),
	)).Render(&rendered, source, doc)
	// goldmark marks each piece of raw HTML it leaves out, and a record has no use for the marks.
	markup := strings.ReplaceAll(rendered.String(), "<!-- raw HTML omitted -->", "")
	return text{
		Lang:            "en",
		Value:           plainBlocks(doc, source),
		SupportingMedia: []media{{Type: "text/html", Value: strings.TrimSpace(markup)}},
	}
}

// plainBlocks writes the blocks under n as plain text, separated by blank lines.
func plainBlocks(n ast.Node, source []byte) string {
	var blocks []string
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if b := plainBlock(c, source); b != "" {
			blocks = append(blocks, b)
		}
	}
	return strings.Join(blocks, "\n\n")
}

// plainBlock writes a block as plain text: headings and paragraphs as their text, code blocks
// indented by four spaces, list items after "- " or their number, and table cells between " | ".
func plainBlock(n ast.Node, source []byte) string {
	switch n := n.(type) {
	case *ast.Paragraph, *ast.Heading, *east.TableRow, *east.TableHeader:
		return plainInline(n, source)
	case *ast.CodeBlock:
		var code strings.Builder
		_, _ = n.Value.WriteTo(&code, source)
		return indent(strings.TrimRight(code.String(), "\n"), "    ", "    ")
	case *ast.Blockquote:
		return indent(plainBlocks(n, source), "> ", "> ")
	case *ast.List:
		var items []string
		number := n.Start
		for item := n.FirstChild(); item != nil; item = item.NextSibling() {
			marker := "- "
			if n.IsOrdered() {
				marker = fmt.Sprintf("%d. ", number)
				number++
			}
			items = append(items, indent(plainBlocks(item, source), marker, strings.Repeat(" ", len(marker))))
		}
		separator := "\n\n"
		if n.IsTight {
			separator = "\n"
		}
		return strings.Join(items, separator)
	case *east.Table, *east.TableBody:
		var rows []string
		for row := n.FirstChild(); row != nil; row = row.NextSibling() {
			rows = append(rows, plainBlock(row, source))
		}
		return strings.Join(rows, "\n")
	case *ast.HTMLBlock, *ast.ThematicBreak:
		return ""
	}
	return plainBlocks(n, source)
}

// plainInline writes the inline content of n as plain text. Links keep their address after their
// text, and cells of a table row are joined with " | ".
func plainInline(n ast.Node, source []byte) string {
	var out strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch c := c.(type) {
		case *ast.Text:
			_, _ = c.Value.WriteTo(&out, source)
			if c.SoftLineBreak() || c.HardLineBreak() {
				out.WriteByte('\n')
			}
		case *ast.CodeSpan:
			_, _ = c.Value.WriteTo(&out, source)
		case *ast.AutoLink:
			_, _ = c.Label.WriteTo(&out, source)
		case *ast.Link:
			label, url := plainInline(c, source), c.Destination.Value(source)
			out.WriteString(label)
			if label != url {
				out.WriteString(" (" + url + ")")
			}
		case *ast.RawHTML:
		case *east.TableCell:
			if c.PreviousSibling() != nil {
				out.WriteString(" | ")
			}
			out.WriteString(plainInline(c, source))
		default:
			out.WriteString(plainInline(c, source))
		}
	}
	return out.String()
}

// indent starts the first line of s with first and the others with rest, leaving blank lines
// empty.
func indent(s, first, rest string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		switch {
		case i == 0:
			lines[i] = first + line
		case line != "":
			lines[i] = rest + line
		}
	}
	return strings.Join(lines, "\n")
}
