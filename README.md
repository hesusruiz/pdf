# pdf

`github.com/hesusruiz/pdf` (`package pdf`) is a Go library built on top of [`folio`](https://github.com/carlos7ags/folio) that renders HTML templates filled with JSON form data into PDF/A-3B documents, then extracts and verifies that structured data back from returned (digitally signed or flattened) PDFs.

It combines **PDF/A-3B embedded JSON attachments**, **PDF named destinations (`/Dests`)**, and **visual form-table geometry** (`PathOps` + `TextSpans` + subtle official-form field codes) so data can be extracted cleanly across real-world signing workflows and cross-checked against tampering without OCR.

---

## Installation

```bash
go get github.com/hesusruiz/pdf
```

---

## Pipeline Overview

1. **Render HTML (`RenderHTML` / `RenderHTMLWithOptions`):** Populate a template containing Jinja-style `{{key}}` placeholders with a JSON object.
2. **Generate PDF (`GeneratePDF`):** Convert the rendered HTML into an A4 PDF/A-3B document embedding the canonical JSON payload (`pdf-data.json`) and optional XMP HMAC integrity digest (`pdfdata:PayloadHMAC`).
3. **Extract from Returned PDF (`Extract` / `ExtractJSON`):** Read the embedded JSON attachment (crossing incremental-update xref chains from PAdES digital signatures) and cross-check it against the rendered table cells—or automatically fall back to visual table extraction if the PDF was flattened.
4. **Compare (`CompareJSON` / `EqualJSON`):** Compare the extracted JSON against the server's expected submission field-by-field.

### Quick Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/hesusruiz/pdf"
)

func main() {
	// 1. Render HTML from template + JSON
	renderedHTML, err := pdf.RenderHTML(templateHTML, inputJSON)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Generate PDF/A-3B with embedded pdf-data.json + optional HMAC in XMP
	pdfBytes, err := pdf.GeneratePDF(renderedHTML, inputJSON, &pdf.PDFOptions{
		HMACSecret: serverSecret, // optional
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3. Later, extract and verify from the returned (signed or flattened) PDF
	res, err := pdf.Extract(pdfBytes, &pdf.ExtractOptions{
		TemplateHTML: templateHTML, // enables flattened-PDF field-code fallback
		HMACSecret:   serverSecret, // verifies XMP pdfdata:PayloadHMAC when attached
	})
	if err != nil {
		log.Fatal(err)
	}
	if len(res.VisualMismatches) > 0 {
		log.Fatalf("visual/attachment mismatch: %+v", res.VisualMismatches)
	}

	// 4. Compare against expected server state
	cmp, err := pdf.CompareJSON(expectedJSON, res.JSON)
	if err != nil {
		log.Fatal(err)
	}
	if !cmp.Equal {
		log.Fatalf("submission mismatch: %+v", cmp)
	}

	fmt.Printf("Extracted cleanly via %s\n", res.Source)
}
```

If you only need strict attachment extraction with automatic visual cross-checking, call `pdf.ExtractJSON(pdfBytes)` directly—it returns an error if `VisualMismatches` is non-empty.

---

## Marking Data Items in the HTML Template

To support both attachment cross-checking and visual/flattened fallback extraction while keeping the printed document natural-looking, templates follow three coordinated conventions (see `testdata/template_pdf.html` and `testdata/sample.json` for a complete example).

### 1. Jinja-Style Placeholders (`{{key}}`)

Placeholders use double curly braces matching `\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}` and resolve dotted paths against nested JSON objects (e.g., `{{date}}`, `{{legal_rep.name}}`, `{{company.tax_id}}`).

- Only scalar JSON values (`string`, `number`, `boolean`, or `null` rendered as `""`) are allowed; pointing a placeholder at an object or array returns an error.
- Substituted values are HTML-escaped (`&` -> `&amp;`, etc.) and decode back to their original characters when extracted from the PDF.
- Missing keys return an error by default. Pass `RenderOptions{AllowMissing: true}` to `RenderHTMLWithOptions` to substitute `""` instead.
- Repeating a placeholder outside form tables (such as `{{legal_rep.name}}` in a signature block) renders normally and is ignored by visual table extraction.
- Call `TemplatePlaceholders(templateHTML)` to list all unique placeholder keys in first-appearance order.

### 2. Three-Column Form Tables with Explicit `background-color`

Structured data rows must be placed in HTML tables with three columns per row:

1. **Code cell (`<td class="field-code">`)**: a numeric code matching `^\d+\.\d+$` (e.g., `0.1`, `1.1`, `2.4`, `3.5`).
2. **Label cell (`<th scope="row">`)**: the human-readable field name (may include `<sup>` footnote references or localized text without affecting extraction).
3. **Value cell (`<td class="field-value">`)**: contains the single `{{...}}` placeholder for that row (may wrap across multiple lines or be empty for optional fields).

**Every cell in the three-column row must have an explicit CSS `background-color`**, including `#ffffff` on `.field-value` (invisible on white paper):

```css
.document-body table.form-table td.field-code {
    width: 7%;
    font-size: 8.5pt;
    font-weight: 500;
    color: #64748b;
    background-color: #f4f7f9;
    text-align: center;
}

.document-body table.form-table th[scope="row"] {
    width: 35%;
    font-weight: 500;
    background-color: #fbfcfd;
    text-align: left;
}

.document-body table.form-table td.field-value {
    width: 58%;
    background-color: #ffffff;
    text-align: left;
}
```

**Why backgrounds are required:** `folio` emits table borders as individual line strokes, whereas cell background colors are emitted as filled rectangle path operators (`re f`). During extraction, `Extract` inspects `page.PathOps()` and groups contiguous triplets of filled rectangles (within a ±2 pt tolerance in Y position, height, and adjacent horizontal edges) whose first cell text matches `^\d+\.\d+$`. Grouping by cell rectangles handles empty optional fields and multi-line wrapped text cleanly without relying on border geometry.

**Template styling caveats:**
- Do **not** keep `td:first-child` in a label-column width rule (as in the original unadapted `testdata/template.html`), or it will force `.field-code` to 38% width.
- Wrap standalone fields like a document date in a 1-row three-column `.form-table` (`0.1 | Date | <time>{{date}}</time>`) so they participate identically in visual extraction and cross-checking.

### 3. Named Destination Anchors (`id="pdf.<json.path>"`)

Wrap the numeric code inside each `<td class="field-code">` in a `<div>` whose `id` equals `"pdf."` followed by the dotted JSON path:

```html
<table class="form-table">
    <tbody>
        <tr>
            <td class="field-code"><div id="pdf.legal_rep.name">1.1</div></td>
            <th scope="row">Name</th>
            <td class="field-value">{{legal_rep.name}}</td>
        </tr>
        <tr>
            <td class="field-code"><div id="pdf.legal_rep.id_number">1.3</div></td>
            <th scope="row">ID card number (optional)</th>
            <td class="field-value">{{legal_rep.id_number}}</td>
        </tr>
    </tbody>
</table>
```

Two `folio/html` behaviors require this exact placement:
- `folio/html` ignores `id` attributes on `<tr>` and `<td>`; only block elements such as `<div>` emit PDF named destinations (`/Dests`).
- `folio/html` omits empty `<div>` elements (zero layout output). Placing `id="pdf.<json.path>"` on `<div id="...">` around the always-non-empty code in `.field-code` guarantees the `/Dests` entry is still emitted even when an optional `.field-value` is `""`.

`ParseTemplateFieldMap(templateHTML)` parses these exact three-column rows to derive the `code -> jsonKey` mapping automatically for flattened PDFs.

---

## Extraction Algorithms & Fallback Chain

`Extract` parses the PDF using `folio/reader` (following incremental-update `/Prev` xref chains added by digital signatures) and sets `ExtractResult.Source` according to the strongest available source:

| Priority | `ExtractionSource` | How it works | When it is used |
|---|---|---|---|
| 1 | `SourceAttachment` | Reads `pdf-data.json` (or `ExtractOptions.AttachmentName`) from Catalog `/AF` (falling back to `/Names` -> `/EmbeddedFiles`), verifies XMP `pdfdata:PayloadHMAC` if `HMACSecret` is set, and cross-checks visual cells (`VisualMismatches`). | Default for PDF/A-3B and PAdES-signed PDFs unless `VisualOnly: true`. |
| 2 | `SourceVisualDests` | Reads filled cell rectangles (`PathOps`) + text (`TextSpans`) and maps rows via Catalog `/Dests` (`pdf.<json.path>`) without needing the HTML template or a `FieldMap`. | Attachment disabled/absent or `VisualOnly: true`, when `/Dests` exist and `IgnoreDests` is false. |
| 3 | `SourceVisualFieldMap` | Maps each row's visible code (`0.1`, `1.1`, ...) to its JSON key via `ExtractOptions.TemplateHTML` (`ParseTemplateFieldMap`) and/or `ExtractOptions.FieldMap`. | `/Dests` stripped (e.g., Print-to-PDF or cloud e-sign flatteners) or `IgnoreDests: true`. |
| 4 | `SourceVisualCodes` | Returns a flat JSON object keyed by visible codes (`{"0.1": "...", "1.1": "..."}`). | Attachment, `/Dests`, and `TemplateHTML`/`FieldMap` are all absent. |

### Signing Workflow Compatibility

| Signing method | Preserved structures | Resulting extraction path |
|---|---|---|
| **PAdES digital certificate signature** (Acrobat, AutoFirma, `folio/sign`) | `/AF`, `/Names`, `/Metadata` (HMAC), `/Dests`, vector content | `SourceAttachment` + optional HMAC + full visual cross-check |
| **Vector Print-to-PDF / destructive e-sign flattener** | Vector rectangles and Unicode text on pages (`/AF`, `/Metadata`, `/Dests` usually stripped) | `SourceVisualFieldMap` (pass `TemplateHTML` or `FieldMap`) |
| **Print, wet-ink sign, and raster scan** | Raster images only (no PDF text/path operators) | Not supported without OCR / QR (outside `pdf`) |

---

## PDF/A-3B, Fonts, Empty Cells, and Integrity

- **Font auto-discovery (`FontConfig`):** PDF/A requires every font to be embedded. `GeneratePDF` automatically discovers static TrueType fonts on Linux, macOS, and Windows (or accepts explicit paths via `PDFOptions.Fonts`) and injects `@font-face` rules covering weights `400`, `500`, and `700` (normal and italic) for all declared CSS font families plus `"helvetica"` fallback.
- **Empty table cells:** In `folio/html`, completely empty `<td>`/`<th>` cells fall back to unembedded Standard-14 Helvetica and fail PDF/A validation. Before conversion, `GeneratePDF` normalizes empty, whitespace-only, or `<br>`-only cells to a non-breaking space (`\u00A0`). Visual extraction trims whitespace so empty optional fields round-trip as `""`.
- **Wrapped text:** Multiple wrapped lines inside a table cell are joined with single spaces, and `extractCellText` guards against Type0 Identity-H fonts reporting `defaultW` (`1000`) as `SpaceWidth`. Visual cross-checking normalizes whitespace runs before comparing against the attachment JSON.
- **HMAC integrity (`PDFOptions.HMACSecret`):** When set with PDF/A-3B enabled, `GeneratePDF` writes `HMAC-SHA256(HMACSecret, canonicalJSON)` as hex in custom XMP property `pdfdata:PayloadHMAC` (namespace `urn:hesusruiz:pdf:pdfa:schema:1p0#`). Passing the same `HMACSecret` in `ExtractOptions` enforces verification on extraction.

---

## Debug Logging

`pdf` emits structured debug logs via Go's standard `log/slog` at `slog.LevelDebug`.

- **Global default logger:** Configure `slog.SetDefault(...)` with `Level: slog.LevelDebug` to capture logs from zero-option calls (`RenderHTML`, `GeneratePDF(..., nil)`, `ExtractJSON`, `CompareJSON`).
- **Per-call logger:** Pass a `*slog.Logger` via `RenderOptions.Logger`, `PDFOptions.Logger` (also forwarded to `folio/html`), or `ExtractOptions.Logger`.

`HMACSecret` values and raw HTML or PDF byte buffers are never logged.

---

## Running Tests

`pdf` targets Go 1.26+:

```bash
go test -v ./...
go vet ./...
```
