// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/carlos7ags/folio/document"
	foliohtml "github.com/carlos7ags/folio/html"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	// DefaultAttachmentName is the default embedded JSON filename in PDF/A-3B documents.
	DefaultAttachmentName = "pdf-data.json"

	xmpNamespace    = "urn:hesusruiz:pdf:pdfa:schema:1p0#"
	xmpPrefix       = "pdfdata"
	xmpHMACProperty = "PayloadHMAC"
)

// PDFOptions configures PDF generation from rendered HTML and JSON payload.
type PDFOptions struct {
	// DisablePDFA turns off PDF/A-3B conformance (enabled by default).
	DisablePDFA bool

	// DisableAttachment skips embedding the JSON payload as a PDF/A-3B
	// associated file (embedded by default).
	DisableAttachment bool

	// AttachmentName overrides the embedded file name (defaults to DefaultAttachmentName).
	AttachmentName string

	// Title overrides the document /Info Title (defaults to HTML <title>, then "Document").
	Title string

	// Fonts overrides auto-discovered TrueType font paths used for @font-face embedding.
	Fonts FontConfig

	// HMACSecret, when non-empty and PDF/A-3B is enabled, stores
	// HMAC-SHA256(HMACSecret, canonicalJSON) in XMP property pdfdata:PayloadHMAC.
	HMACSecret []byte

	// Logger receives debug diagnostic logs during PDF generation. Nil uses slog.Default().
	Logger *slog.Logger
}

// GeneratePDF converts renderedHTML into a PDF document, embedding dataJSON as a
// PDF/A-3B associated file (unless disabled) and ensuring all fonts/cells meet
// PDF/A-3B and visual extraction requirements.
func GeneratePDF(renderedHTML string, dataJSON []byte, opts *PDFOptions) ([]byte, error) {
	if opts == nil {
		opts = &PDFOptions{}
	}
	log := resolveLogger(opts.Logger)
	log.Debug("pdf: generating PDF",
		"html_bytes", len(renderedHTML),
		"json_bytes", len(dataJSON),
		"pdfa", !opts.DisablePDFA,
		"attachment", !opts.DisableAttachment,
		"hmac", len(opts.HMACSecret) > 0,
	)

	canonical, err := canonicalizeJSON(dataJSON)
	if err != nil {
		return nil, err
	}

	var fonts FontConfig
	var fontErr error
	if opts.Fonts.Regular != "" || !opts.DisablePDFA {
		fonts, fontErr = resolveFontConfig(opts.Fonts, log)
		if fontErr != nil {
			return nil, fontErr
		}
	} else {
		fonts, _ = resolveFontConfig(opts.Fonts, log)
	}

	preparedHTML, err := prepareHTMLForPDF(renderedHTML, fonts, log)
	if err != nil {
		return nil, err
	}

	doc := document.NewDocument(document.PageSizeA4)
	htmlOpts := &foliohtml.Options{
		AllowAbsolutePaths: true,
		FallbackFontPath:   fonts.Regular,
		Logger:             log,
	}
	if err := doc.AddHTML(preparedHTML, htmlOpts); err != nil {
		return nil, fmt.Errorf("pdf: convert HTML to PDF: %w", err)
	}

	if opts.Title != "" {
		doc.Info.Title = opts.Title
	} else if doc.Info.Title == "" {
		doc.Info.Title = "Document"
	}
	log.Debug("pdf: converted HTML to layout document", "title", doc.Info.Title)

	if !opts.DisablePDFA {
		cfg := document.PdfAConfig{Level: document.PdfA3B}
		if len(opts.HMACSecret) > 0 {
			macHex := computeHMAC(opts.HMACSecret, canonical)
			cfg.XMPSchemas = []document.XMPSchema{{
				Schema:       "PDF Structured Form Schema",
				NamespaceURI: xmpNamespace,
				Prefix:       xmpPrefix,
				Properties: []document.XMPSchemaProperty{{
					Name:        xmpHMACProperty,
					ValueType:   "Text",
					Category:    "external",
					Description: "Hex-encoded HMAC-SHA256 of canonical embedded JSON payload",
				}},
			}}
			cfg.XMPProperties = []document.XMPPropertyBlock{{
				Namespace: xmpNamespace,
				Prefix:    xmpPrefix,
				Properties: []document.XMPProperty{{
					Name:  xmpHMACProperty,
					Value: macHex,
				}},
			}}
		}
		doc.SetPdfA(cfg)
		log.Debug("pdf: configured PDF/A-3B conformance", "hmac_embedded", len(opts.HMACSecret) > 0)
	}

	if !opts.DisableAttachment {
		attachName := opts.AttachmentName
		if attachName == "" {
			attachName = DefaultAttachmentName
		}
		doc.AttachFile(document.FileAttachment{
			FileName:       attachName,
			MIMEType:       "application/json",
			Description:    "Structured document form data",
			AFRelationship: "Data",
			Data:           canonical,
		})
		log.Debug("pdf: attached JSON payload to PDF", "filename", attachName, "bytes", len(canonical))
	}

	pdfBytes, err := doc.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("pdf: generate PDF: %w", err)
	}
	log.Debug("pdf: generated PDF", "pdf_bytes", len(pdfBytes))
	return pdfBytes, nil
}

func prepareHTMLForPDF(renderedHTML string, fonts FontConfig, log *slog.Logger) (string, error) {
	withFonts := injectFontFacesCSS(renderedHTML, fonts, log)

	doc, err := html.Parse(strings.NewReader(withFonts))
	if err != nil {
		return "", fmt.Errorf("pdf: parse rendered HTML: %w", err)
	}

	// Empty table cells cause folio/html to fall back to unembedded Helvetica,
	// which fails PDF/A-3B validation. Replace empty/whitespace/<br>-only cell
	// contents with a non-breaking space (\u00A0) so folio uses the embedded
	// cell font while keeping the cell visually blank.
	normalizedCells := 0
	var normalizeCells func(*html.Node)
	normalizeCells = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.DataAtom == atom.Td || n.DataAtom == atom.Th) {
			if isEffectivelyEmptyCell(n) {
				for ch := n.FirstChild; ch != nil; {
					next := ch.NextSibling
					n.RemoveChild(ch)
					ch = next
				}
				n.AppendChild(&html.Node{
					Type: html.TextNode,
					Data: "\u00A0",
				})
				normalizedCells++
				return
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			normalizeCells(ch)
		}
	}
	normalizeCells(doc)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return "", fmt.Errorf("pdf: serialize prepared HTML: %w", err)
	}
	resolveLogger(log).Debug("pdf: prepared HTML for PDF",
		"normalized_empty_cells", normalizedCells,
		"output_bytes", buf.Len(),
	)
	return buf.String(), nil
}

func isEffectivelyEmptyCell(cell *html.Node) bool {
	if hasNonTextVisualElement(cell) {
		return false
	}
	return strings.TrimSpace(nodeText(cell)) == ""
}

func hasNonTextVisualElement(n *html.Node) bool {
	if n.Type == html.ElementNode {
		switch n.DataAtom {
		case atom.Img, atom.Svg, atom.Input, atom.Select, atom.Textarea, atom.Button:
			return true
		}
	}
	for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
		if hasNonTextVisualElement(ch) {
			return true
		}
	}
	return false
}

func computeHMAC(secret, data []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
