// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"io"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var (
	placeholderRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}`)
	fieldCodeRe   = regexp.MustCompile(`^\d+\.\d+$`)
)

// RenderOptions configures HTML template rendering.
type RenderOptions struct {
	// AllowMissing controls how placeholders without a matching JSON key are
	// handled. When false (default), RenderHTML returns an error listing all
	// missing keys. When true, missing keys are replaced with "".
	AllowMissing bool

	// Logger receives debug diagnostic logs during rendering. Nil uses slog.Default().
	Logger *slog.Logger
}

func resolveLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

// RenderHTML substitutes Jinja-style {{key}} placeholders in templateHTML using
// scalar values from dataJSON (supporting dotted paths like {{legal_rep.name}}).
// Missing keys return an error; HTML special characters in values are escaped.
func RenderHTML(templateHTML string, dataJSON []byte) (string, error) {
	return RenderHTMLWithOptions(templateHTML, dataJSON, RenderOptions{})
}

// RenderHTMLWithOptions behaves like RenderHTML with configurable options.
func RenderHTMLWithOptions(templateHTML string, dataJSON []byte, opts RenderOptions) (string, error) {
	log := resolveLogger(opts.Logger)
	log.Debug("pdf: rendering HTML template",
		"template_bytes", len(templateHTML),
		"json_bytes", len(dataJSON),
		"allow_missing", opts.AllowMissing,
	)

	root, err := decodeJSONObject(dataJSON)
	if err != nil {
		return "", err
	}

	var missing []string
	missingSeen := make(map[string]bool)
	var lookupErr error
	replacements := 0

	rendered := placeholderRe.ReplaceAllStringFunc(templateHTML, func(match string) string {
		if lookupErr != nil {
			return match
		}
		sub := placeholderRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		key := sub[1]
		val, ok, err := lookupJSONPath(root, key)
		if err != nil {
			lookupErr = fmt.Errorf("pdf: key %q: %w", key, err)
			return match
		}
		if !ok {
			if opts.AllowMissing {
				replacements++
				log.Debug("pdf: missing placeholder replaced with empty string", "key", key)
				return ""
			}
			if !missingSeen[key] {
				missingSeen[key] = true
				missing = append(missing, key)
			}
			return match
		}
		replacements++
		return stdhtml.EscapeString(val)
	})

	if lookupErr != nil {
		return "", lookupErr
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("pdf: missing JSON keys for placeholders: %s", strings.Join(missing, ", "))
	}
	log.Debug("pdf: rendered HTML template",
		"replacements", replacements,
		"output_bytes", len(rendered),
	)
	return rendered, nil
}

// TemplatePlaceholders returns the unique placeholder paths found in
// templateHTML in first-appearance order.
func TemplatePlaceholders(templateHTML string) []string {
	matches := placeholderRe.FindAllStringSubmatch(templateHTML, -1)
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}

// ParseTemplateFieldMap inspects table rows in templateHTML and returns a
// mapping from official-form field code (e.g. "1.1") to dotted JSON key path
// (e.g. "legal_rep.name").
func ParseTemplateFieldMap(templateHTML string) map[string]string {
	return parseTemplateFieldMap(templateHTML, nil)
}

func parseTemplateFieldMap(templateHTML string, log *slog.Logger) map[string]string {
	out := make(map[string]string)
	if strings.TrimSpace(templateHTML) == "" {
		return out
	}
	doc, err := html.Parse(strings.NewReader(templateHTML))
	if err != nil {
		return out
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.DataAtom == atom.Tr {
			code, jsonKey := extractRowFieldMapping(n)
			if code != "" && jsonKey != "" {
				out[code] = jsonKey
			}
			return
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	resolveLogger(log).Debug("pdf: parsed template field map", "fields", len(out))
	return out
}

func extractRowFieldMapping(tr *html.Node) (code, jsonKey string) {
	var cells []*html.Node
	for ch := tr.FirstChild; ch != nil; ch = ch.NextSibling {
		if ch.Type == html.ElementNode && (ch.DataAtom == atom.Td || ch.DataAtom == atom.Th) {
			cells = append(cells, ch)
		}
	}
	if len(cells) < 2 {
		return "", ""
	}

	var codeCell, valueCell *html.Node
	for _, cell := range cells {
		if hasClass(cell, "field-code") {
			codeCell = cell
		}
		if hasClass(cell, "field-value") {
			valueCell = cell
		}
	}
	if codeCell == nil {
		txt := strings.TrimSpace(nodeText(cells[0]))
		if fieldCodeRe.MatchString(txt) {
			codeCell = cells[0]
		}
	}
	if codeCell == nil {
		return "", ""
	}
	code = strings.TrimSpace(nodeText(codeCell))
	if !fieldCodeRe.MatchString(code) {
		return "", ""
	}

	if valueCell == nil {
		last := cells[len(cells)-1]
		if last != codeCell {
			valueCell = last
		}
	}
	if valueCell == nil {
		return "", ""
	}

	matches := placeholderRe.FindAllStringSubmatch(nodeText(valueCell), -1)
	if len(matches) != 1 || len(matches[0]) < 2 {
		return "", ""
	}
	return code, matches[0][1]
}

func hasClass(n *html.Node, target string) bool {
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			for _, cls := range strings.Fields(attr.Val) {
				if cls == target {
					return true
				}
			}
		}
	}
	return false
}

func nodeText(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(cur *html.Node) {
		if cur.Type == html.TextNode {
			sb.WriteString(cur.Data)
			return
		}
		for ch := cur.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(n)
	return sb.String()
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("pdf: empty JSON payload")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()

	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("pdf: decode JSON object: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("pdf: JSON payload must be an object, not null")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("pdf: unexpected trailing data after JSON object")
	}
	return obj, nil
}

func canonicalizeJSON(data []byte) ([]byte, error) {
	obj, err := decodeJSONObject(data)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("pdf: marshal canonical JSON: %w", err)
	}
	return out, nil
}

func lookupJSONPath(root map[string]any, path string) (string, bool, error) {
	if path == "" {
		return "", false, fmt.Errorf("empty path")
	}
	parts := strings.Split(path, ".")
	cur := any(root)
	for i, part := range parts {
		if part == "" {
			return "", false, fmt.Errorf("empty segment in path %q", path)
		}
		m, ok := cur.(map[string]any)
		if !ok {
			if cur == nil {
				return "", false, nil
			}
			return "", false, fmt.Errorf("segment %q is not an object", strings.Join(parts[:i], "."))
		}
		next, exists := m[part]
		if !exists {
			return "", false, nil
		}
		cur = next
	}
	val, err := scalarToString(cur)
	if err != nil {
		return "", false, err
	}
	return val, true, nil
}

func scalarToString(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case string:
		return x, nil
	case json.Number:
		return x.String(), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	default:
		return "", fmt.Errorf("expected scalar value, got %T", v)
	}
}

func setNestedPath(root map[string]any, path, value string) error {
	if path == "" {
		return fmt.Errorf("pdf: empty JSON path")
	}
	parts := strings.Split(path, ".")
	cur := root
	for i := 0; i < len(parts)-1; i++ {
		seg := parts[i]
		if seg == "" {
			return fmt.Errorf("pdf: empty segment in JSON path %q", path)
		}
		existing, exists := cur[seg]
		if !exists {
			child := make(map[string]any)
			cur[seg] = child
			cur = child
			continue
		}
		child, ok := existing.(map[string]any)
		if !ok {
			return fmt.Errorf("pdf: path conflict at %q in %q", strings.Join(parts[:i+1], "."), path)
		}
		cur = child
	}
	leaf := parts[len(parts)-1]
	if leaf == "" {
		return fmt.Errorf("pdf: empty leaf in JSON path %q", path)
	}
	cur[leaf] = value
	return nil
}

func flattenJSONObject(root map[string]any) map[string]string {
	out := make(map[string]string)
	flattenInto(root, "", out)
	return out
}

func flattenInto(m map[string]any, prefix string, out map[string]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch x := v.(type) {
		case map[string]any:
			flattenInto(x, key, out)
		default:
			if s, err := scalarToString(x); err == nil {
				out[key] = s
			} else if raw, merr := json.Marshal(x); merr == nil {
				out[key] = string(raw)
			}
		}
	}
}
