// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

// Package pdf renders HTML document templates filled with JSON data into
// PDF/A-3B files and extracts and verifies that structured data back from
// returned (possibly digitally signed or flattened) PDFs.
//
// The library is built on top of github.com/carlos7ags/folio and combines
// machine-readable PDF/A-3B attachments, PDF named destinations (/Dests),
// and visual form-table geometry so data can be recovered reliably across
// different PDF workflows and cross-checked against tampering.
//
// # Pipeline Overview
//
// A typical onboarding or legal-form workflow uses four steps:
//
//  1. Render the HTML template with captured JSON form data via [RenderHTML] or
//     [RenderHTMLWithOptions].
//  2. Convert the rendered HTML into a PDF/A-3B document carrying the canonical
//     JSON payload via [GeneratePDF].
//  3. Send the PDF to the user or legal representative for signing, then feed
//     the returned PDF bytes into [ExtractJSON] or [Extract].
//  4. Compare the extracted JSON against the server's expected submission via
//     [CompareJSON] or [EqualJSON].
//
// Example:
//
//	rendered, err := pdf.RenderHTML(templateHTML, inputJSON)
//	if err != nil {
//		return err
//	}
//
//	pdfBytes, err := pdf.GeneratePDF(rendered, inputJSON, &pdf.PDFOptions{
//		HMACSecret: serverSecret, // optional XMP integrity tag
//	})
//	if err != nil {
//		return err
//	}
//
//	// Later, after the signed PDF is returned:
//	res, err := pdf.Extract(returnedPDF, &pdf.ExtractOptions{
//		TemplateHTML: templateHTML, // enables flattened-PDF code fallback
//		HMACSecret:   serverSecret, // verifies XMP pdfdata:PayloadHMAC when attached
//	})
//	if err != nil {
//		return err
//	}
//	if len(res.VisualMismatches) > 0 {
//		return fmt.Errorf("visual/attachment mismatch: %+v", res.VisualMismatches)
//	}
//
//	cmp, err := pdf.CompareJSON(expectedJSON, res.JSON)
//	if err != nil || !cmp.Equal {
//		return fmt.Errorf("submission mismatch: %+v", cmp)
//	}
//
// # Marking Data Items in the HTML Template
//
// To enable both attachment cross-checking and visual/flattened fallback
// extraction while keeping printed documents natural-looking, mark structured
// data items in the HTML template using three coordinated conventions:
//
// ## 1. Jinja-Style Placeholders ({{key}})
//
// Placeholders use double curly braces matching `\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}`
// and resolve dotted paths against nested JSON objects (for example `{{date}}`,
// `{{legal_rep.name}}`, `{{company.tax_id}}`).
//
//   - Only scalar JSON values (string, number, boolean, or null rendered as "")
//     are accepted; pointing a placeholder at an object or array returns an
//     error.
//   - Values are HTML-escaped on substitution, so special characters such as `&`
//     render safely in HTML and decode back to their original characters in PDF
//     text extraction.
//   - By default [RenderHTML] returns an error if any placeholder key is absent
//     from the JSON object. Set [RenderOptions.AllowMissing] to true to
//     substitute "" for missing keys instead.
//   - Non-table uses of the same placeholder (for example repeating
//     `{{legal_rep.name}}` in a signature block) are rendered normally and are
//     ignored by visual table extraction.
//
// Inspect unique placeholders in template order with [TemplatePlaceholders].
//
// ## 2. Three-Column Form Tables with Explicit Cell Backgrounds
//
// Structured fields must appear in HTML tables with three columns per row:
//
//  1. Code cell (`<td class="field-code">`): a short numeric form code matching
//     `^\d+\.\d+$` (for example `0.1`, `1.1`, `2.4`, `3.5`).
//  2. Label cell (`<th scope="row">`): the human-readable field name (may
//     contain footnote superscripts like `<sup>1</sup>` or localized wording
//     without affecting extraction).
//  3. Value cell (`<td class="field-value">`): contains the single `{{...}}`
//     placeholder for that row (may wrap across multiple lines or be empty for
//     optional fields).
//
// Every cell in the three-column row must have an explicit CSS `background-color`
// (including `#ffffff` on `.field-value`, which is invisible on white paper):
//
//	<style>
//	  table.form-table td.field-code {
//	    width: 7%;
//	    font-size: 8.5pt;
//	    color: #64748b;
//	    background-color: #f4f7f9;
//	    text-align: center;
//	  }
//	  table.form-table th[scope="row"] {
//	    width: 35%;
//	    font-weight: 500;
//	    background-color: #fbfcfd;
//	    text-align: left;
//	  }
//	  table.form-table td.field-value {
//	    width: 58%;
//	    background-color: #ffffff;
//	    text-align: left;
//	  }
//	</style>
//
// Why backgrounds are required: `folio` draws table borders as line segments,
// whereas cell background colors are emitted as filled rectangle path operators
// (`re f`). During extraction, [Extract] reads each page's `PathOps()` and
// groups contiguous triplets of filled rectangles (within a ±2 pt tolerance in
// Y position, height, and adjacent horizontal edges) whose first cell text
// matches `^\d+\.\d+$`. Grouping by filled rectangles handles empty optional
// cells and multi-line wrapped values cleanly without relying on border geometry.
//
// Watch out for `td:first-child` rules in existing stylesheets: remove
// `td:first-child` from any label-column width rule so it does not override
// `.field-code`'s narrow width. Standalone fields such as a document date
// should also be placed in a single-row 3-column `.form-table` (for example
// `0.1 | Date | <time>{{date}}</time>`) so they participate identically in
// visual extraction and cross-checking.
//
// ## 3. Named Destination Anchors (id="pdf.<json.path>")
//
// Wrap the numeric code inside each `.field-code` cell in a `<div>` whose `id`
// attribute equals `"pdf."` followed by the dotted JSON path:
//
//	<table class="form-table">
//	  <tbody>
//	    <tr>
//	      <td class="field-code"><div id="pdf.legal_rep.name">1.1</div></td>
//	      <th scope="row">Name</th>
//	      <td class="field-value">{{legal_rep.name}}</td>
//	    </tr>
//	    <tr>
//	      <td class="field-code"><div id="pdf.legal_rep.id_number">1.3</div></td>
//	      <th scope="row">ID card number (optional)</th>
//	      <td class="field-value">{{legal_rep.id_number}}</td>
//	    </tr>
//	  </tbody>
//	</table>
//
// Two `folio/html` behaviors dictate this exact markup:
//
//   - `folio/html` ignores `id` attributes on `<tr>` and `<td>` elements; only
//     block elements such as `<div>` emit PDF named destinations (`/Dests`).
//   - `folio/html` omits empty `<div>` elements (zero layout elements), so
//     placing `id="pdf.<json.path>"` inside `<td class="field-value">` would
//     drop the anchor whenever an optional field is `""`. Placing the `<div>`
//     around the non-empty code in `<td class="field-code">` guarantees that
//     the `/Dests` entry is always emitted on the row.
//
// Putting these rules together lets [ParseTemplateFieldMap] automatically
// extract the `code -> jsonKey` mapping directly from the template HTML when
// needed for flattened PDFs.
//
// # Extraction Algorithms and Fallback Chain
//
// [Extract] parses the PDF with `folio/reader` (which follows incremental-update
// xref chains from digital signatures) and records [ExtractResult.Source]
// according to the strongest available data source:
//
//  1. [SourceAttachment]: When [ExtractOptions.VisualOnly] is false and the
//     embedded JSON file ([DefaultAttachmentName], `"pdf-data.json"`, or
//     [ExtractOptions.AttachmentName]) exists, [Extract] reads it from Catalog
//     `/AF` (falling back to `/Names` -> `/EmbeddedFiles`), verifies the
//     `pdfdata:PayloadHMAC` XMP property when [ExtractOptions.HMACSecret] is
//     provided, validates and canonicalizes the JSON, and (unless
//     [ExtractOptions.SkipVisualCrossCheck] is set) compares every extracted
//     visual table cell against the attachment JSON. Any mismatch populates
//     [ExtractResult.VisualMismatches], and [ExtractJSON] returns an error to
//     flag tampered or out-of-sync PDFs.
//  2. [SourceVisualDests]: When no attachment is present (or
//     [ExtractOptions.VisualOnly] is true) and Catalog `/Dests` contains
//     `pdf.<json.path>` anchors matching the table rows' Y coordinates, [Extract]
//     reconstructs the full nested JSON object directly from the visual table
//     cells without needing the original HTML template or an external field map.
//  3. [SourceVisualFieldMap]: When `/Dests` were stripped (for example by
//     Print-to-PDF or destructive cloud e-sign flatteners) or
//     [ExtractOptions.IgnoreDests] is set, [Extract] maps each row's visible
//     field code (`0.1`, `1.1`, ...) to its JSON key using
//     [ExtractOptions.TemplateHTML] (via [ParseTemplateFieldMap]) and/or
//     [ExtractOptions.FieldMap].
//  4. [SourceVisualCodes]: When attachment, `/Dests`, and template/field-map
//     mappings are all unavailable, [Extract] still extracts every form row and
//     returns a flat JSON object keyed by the visible codes (`{"0.1": "...", ...}`).
//
// Workflow preservation summary:
//
//   - PAdES digital signatures (Acrobat, AutoFirma, `folio/sign`): preserve
//     `/AF`, `/Names`, `/Metadata` (HMAC), `/Dests`, and page content streams
//     ([SourceAttachment] + HMAC + visual cross-check all work).
//   - Vector Print-to-PDF / destructive e-sign flatteners: strip catalog metadata
//     and attachments, leaving vector rectangles and text intact
//     ([SourceVisualFieldMap] recovers nested JSON using the field codes).
//   - Print, wet-ink sign, and raster scan: produces image-only pages with no
//     PDF vector/text operators; recovery from scans requires OCR or QR decoding
//     outside this package.
//
// # PDF/A-3B Fonts, Empty Cells, and Text Normalization
//
// By default [GeneratePDF] enables PDF/A-3B conformance and embeds the
// canonicalized JSON attachment (`AFRelationship: Data`). To satisfy PDF/A-3B's
// requirement that every font be embedded:
//
//   - Static TrueType fonts are auto-discovered on Linux, macOS, and Windows (or
//     supplied explicitly via [PDFOptions.Fonts]) and injected as `@font-face`
//     rules covering weights 400, 500, and 700 (normal and italic) for all
//     declared CSS families as well as `"helvetica"` fallback.
//   - Empty, whitespace-only, or `<br>`-only `<td>`/`<th>` cells are normalized
//     to a non-breaking space (`\u00A0`) before HTML-to-PDF conversion so
//     `folio/html` does not fall back to unembedded Standard-14 Helvetica.
//     Visual extraction trims whitespace so empty optional fields return `""`.
//   - Wrapped multi-line spans within a cell are joined with single spaces, and
//     visual cross-checking normalizes whitespace runs before comparison.
//   - When [PDFOptions.HMACSecret] is set (with PDF/A-3B enabled), `GeneratePDF`
//     computes `HMAC-SHA256(HMACSecret, canonicalJSON)` and writes the hex
//     digest to custom XMP property `pdfdata:PayloadHMAC` (namespace
//     `urn:hesusruiz:pdf:pdfa:schema:1p0#`).
//
// # Debug Logging
//
// The package emits diagnostic logs via [log/slog] at [log/slog.LevelDebug].
// Callers can enable debug output globally using [log/slog.SetDefault] or pass
// a per-call logger via [RenderOptions.Logger], [PDFOptions.Logger], or
// [ExtractOptions.Logger] (also forwarded to `folio/html` during PDF
// conversion). Secret keys (`HMACSecret`) and raw HTML or PDF byte buffers are
// never written to logs.
package pdf
