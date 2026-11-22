// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math"
	"sort"
	"strings"

	"github.com/carlos7ags/folio/core"
	"github.com/carlos7ags/folio/reader"
)

// ExtractionSource identifies where extracted data originated.
type ExtractionSource string

const (
	// SourceAttachment indicates the JSON payload was read from the embedded PDF/A-3B file.
	SourceAttachment ExtractionSource = "attachment"
	// SourceVisualDests indicates visual table cells were mapped to JSON keys via /Dests anchors.
	SourceVisualDests ExtractionSource = "visual_dests"
	// SourceVisualFieldMap indicates visual table cells were mapped via TemplateHTML or FieldMap.
	SourceVisualFieldMap ExtractionSource = "visual_field_map"
	// SourceVisualCodes indicates visual table values were keyed directly by official-form codes.
	SourceVisualCodes ExtractionSource = "visual_codes"

	destAnchorPrefix = "pdf."
)

// ExtractOptions configures PDF data extraction and verification.
type ExtractOptions struct {
	// AttachmentName overrides the embedded filename to look up (defaults to DefaultAttachmentName).
	AttachmentName string

	// VisualOnly ignores embedded attachments and extracts solely from visual tables.
	VisualOnly bool

	// IgnoreDests skips /Dests anchor resolution during visual extraction.
	IgnoreDests bool

	// TemplateHTML provides a fallback code-to-JSON-key mapping when /Dests are absent.
	TemplateHTML string

	// FieldMap provides explicit code-to-JSON-key overrides (merged over TemplateHTML).
	FieldMap map[string]string

	// SkipVisualCrossCheck disables comparing extracted attachment values against visual cells.
	SkipVisualCrossCheck bool

	// HMACSecret, when non-empty, requires and verifies XMP pdfdata:PayloadHMAC against
	// the extracted attachment bytes.
	HMACSecret []byte

	// Logger receives debug diagnostic logs during extraction. Nil uses slog.Default().
	Logger *slog.Logger
}

// VisualField represents one extracted row from a visual form table.
type VisualField struct {
	Code    string
	Label   string
	Value   string
	JSONKey string
	Page    int
}

// FieldMismatch records a difference between expected and actual field values.
type FieldMismatch struct {
	Key      string
	Expected string
	Actual   string
}

// ExtractResult holds the extracted JSON payload, provenance, and cross-check findings.
type ExtractResult struct {
	JSON             []byte
	Source           ExtractionSource
	VisualFields     []VisualField
	VisualMismatches []FieldMismatch
	HMACVerified     bool
}

// Extract reads structured JSON data from pdfBytes, preferring the embedded
// PDF/A-3B attachment (cross-checked against the rendered table) and falling
// back to visual table extraction if the PDF has been flattened.
func Extract(pdfBytes []byte, opts *ExtractOptions) (*ExtractResult, error) {
	if opts == nil {
		opts = &ExtractOptions{}
	}
	log := resolveLogger(opts.Logger)

	attachName := opts.AttachmentName
	if attachName == "" {
		attachName = DefaultAttachmentName
	}

	log.Debug("pdf: extracting data from PDF",
		"pdf_bytes", len(pdfBytes),
		"attachment_name", attachName,
		"visual_only", opts.VisualOnly,
		"ignore_dests", opts.IgnoreDests,
		"hmac_check", len(opts.HMACSecret) > 0,
	)

	r, err := reader.Parse(pdfBytes)
	if err != nil {
		return nil, fmt.Errorf("pdf: parse PDF: %w", err)
	}
	log.Debug("pdf: parsed PDF", "version", r.Version(), "pages", r.PageCount())

	var attachBytes []byte
	var hasAttach bool
	if !opts.VisualOnly {
		attachBytes, hasAttach, err = extractAttachment(r, attachName, log)
		if err != nil {
			return nil, err
		}
	}

	visualFields, usedDests, usedFieldMap, err := extractVisualFields(r, opts, log)
	if err != nil {
		return nil, err
	}

	res := &ExtractResult{
		VisualFields: visualFields,
	}

	if hasAttach && !opts.VisualOnly {
		canonicalAttach, err := canonicalizeJSON(attachBytes)
		if err != nil {
			return nil, fmt.Errorf("pdf: attachment %q: %w", attachName, err)
		}

		if len(opts.HMACSecret) > 0 {
			if err := verifyXMPHMAC(r, attachBytes, canonicalAttach, opts.HMACSecret, log); err != nil {
				return nil, err
			}
			res.HMACVerified = true
		}

		if !opts.SkipVisualCrossCheck && len(visualFields) > 0 {
			attachObj, err := decodeJSONObject(canonicalAttach)
			if err != nil {
				return nil, err
			}
			checkedFields := 0
			for _, vf := range visualFields {
				if vf.JSONKey == "" {
					continue
				}
				checkedFields++
				expectedVal, ok, err := lookupJSONPath(attachObj, vf.JSONKey)
				if err != nil {
					errMsg := fmt.Sprintf("<error: %v>", err)
					log.Debug("pdf: visual cross-check mismatch",
						"key", vf.JSONKey,
						"attachment", errMsg,
						"visual", vf.Value,
					)
					res.VisualMismatches = append(res.VisualMismatches, FieldMismatch{
						Key:      vf.JSONKey,
						Expected: errMsg,
						Actual:   vf.Value,
					})
					continue
				}
				if !ok {
					log.Debug("pdf: visual cross-check mismatch",
						"key", vf.JSONKey,
						"attachment", "<missing>",
						"visual", vf.Value,
					)
					res.VisualMismatches = append(res.VisualMismatches, FieldMismatch{
						Key:      vf.JSONKey,
						Expected: "<missing>",
						Actual:   vf.Value,
					})
					continue
				}
				if normalizeSpaces(expectedVal) != normalizeSpaces(vf.Value) {
					log.Debug("pdf: visual cross-check mismatch",
						"key", vf.JSONKey,
						"attachment", expectedVal,
						"visual", vf.Value,
					)
					res.VisualMismatches = append(res.VisualMismatches, FieldMismatch{
						Key:      vf.JSONKey,
						Expected: expectedVal,
						Actual:   vf.Value,
					})
				}
			}
			log.Debug("pdf: completed visual cross-check",
				"checked_fields", checkedFields,
				"mismatches", len(res.VisualMismatches),
			)
		}

		res.Source = SourceAttachment
		res.JSON = canonicalAttach
		log.Debug("pdf: extraction complete",
			"source", res.Source,
			"json_bytes", len(res.JSON),
			"visual_fields", len(res.VisualFields),
			"mismatches", len(res.VisualMismatches),
			"hmac_verified", res.HMACVerified,
		)
		return res, nil
	}

	if len(visualFields) == 0 {
		return nil, fmt.Errorf("pdf: no attachment %q and no extractable visual form fields found", attachName)
	}

	allHaveKeys := true
	for _, vf := range visualFields {
		if vf.JSONKey == "" {
			allHaveKeys = false
			break
		}
	}

	if allHaveKeys {
		root := make(map[string]any)
		for _, vf := range visualFields {
			if err := setNestedPath(root, vf.JSONKey, vf.Value); err != nil {
				return nil, err
			}
		}
		outJSON, err := json.Marshal(root)
		if err != nil {
			return nil, fmt.Errorf("pdf: marshal extracted JSON: %w", err)
		}
		res.JSON = outJSON
		if usedDests && !usedFieldMap {
			res.Source = SourceVisualDests
		} else {
			res.Source = SourceVisualFieldMap
		}
		log.Debug("pdf: extraction complete",
			"source", res.Source,
			"json_bytes", len(res.JSON),
			"visual_fields", len(res.VisualFields),
			"mismatches", len(res.VisualMismatches),
			"hmac_verified", res.HMACVerified,
		)
		return res, nil
	}

	flat := make(map[string]string, len(visualFields))
	for _, vf := range visualFields {
		flat[vf.Code] = vf.Value
	}
	outJSON, err := json.Marshal(flat)
	if err != nil {
		return nil, fmt.Errorf("pdf: marshal visual code JSON: %w", err)
	}
	res.JSON = outJSON
	res.Source = SourceVisualCodes
	log.Debug("pdf: extraction complete",
		"source", res.Source,
		"json_bytes", len(res.JSON),
		"visual_fields", len(res.VisualFields),
		"mismatches", len(res.VisualMismatches),
		"hmac_verified", res.HMACVerified,
	)
	return res, nil
}

// ExtractJSON extracts the structured JSON object from pdfBytes and verifies
// that embedded attachment data agrees with the visual table fields.
func ExtractJSON(pdfBytes []byte) ([]byte, error) {
	res, err := Extract(pdfBytes, nil)
	if err != nil {
		return nil, err
	}
	if len(res.VisualMismatches) > 0 {
		parts := make([]string, 0, len(res.VisualMismatches))
		for _, mm := range res.VisualMismatches {
			parts = append(parts, fmt.Sprintf("%s (attachment=%q visual=%q)", mm.Key, mm.Expected, mm.Actual))
		}
		return nil, fmt.Errorf("pdf: attachment/visual mismatch detected: %s", strings.Join(parts, "; "))
	}
	return res.JSON, nil
}

func extractAttachment(r *reader.PdfReader, targetName string, log *slog.Logger) ([]byte, bool, error) {
	catalog := r.Catalog()
	if catalog == nil {
		log.Debug("pdf: attachment not found (missing catalog)", "filename", targetName)
		return nil, false, nil
	}

	// Path A: PDF/A-3 / PDF 2.0 /AF array on Catalog.
	if afObj := catalog.Get("AF"); afObj != nil {
		resolved, err := r.ResolveObject(afObj)
		if err != nil {
			return nil, false, fmt.Errorf("pdf: resolve /AF: %w", err)
		}
		if afArr, ok := resolved.(*core.PdfArray); ok {
			for _, elem := range afArr.All() {
				data, matched, err := readMatchingFilespec(r, elem, targetName)
				if err != nil {
					return nil, false, err
				}
				if matched {
					log.Debug("pdf: extracted attachment via /AF", "filename", targetName, "bytes", len(data))
					return data, true, nil
				}
			}
		}
	}

	// Path B: /Names -> /EmbeddedFiles name tree.
	if namesObj := catalog.Get("Names"); namesObj != nil {
		resolved, err := r.ResolveObject(namesObj)
		if err != nil {
			return nil, false, fmt.Errorf("pdf: resolve /Names: %w", err)
		}
		if namesDict, ok := resolved.(*core.PdfDictionary); ok {
			if efObj := namesDict.Get("EmbeddedFiles"); efObj != nil {
				efResolved, err := r.ResolveObject(efObj)
				if err != nil {
					return nil, false, fmt.Errorf("pdf: resolve /EmbeddedFiles: %w", err)
				}
				if efDict, ok := efResolved.(*core.PdfDictionary); ok {
					data, found, err := walkEmbeddedNameTree(r, efDict, targetName)
					if err != nil {
						return nil, false, err
					}
					if found {
						log.Debug("pdf: extracted attachment via /Names/EmbeddedFiles", "filename", targetName, "bytes", len(data))
						return data, true, nil
					}
				}
			}
		}
	}

	log.Debug("pdf: attachment not found", "filename", targetName)
	return nil, false, nil
}

func walkEmbeddedNameTree(r *reader.PdfReader, node *core.PdfDictionary, targetName string) ([]byte, bool, error) {
	if namesObj := node.Get("Names"); namesObj != nil {
		resolved, err := r.ResolveObject(namesObj)
		if err != nil {
			return nil, false, fmt.Errorf("pdf: resolve EmbeddedFiles /Names: %w", err)
		}
		if arr, ok := resolved.(*core.PdfArray); ok {
			for i := 0; i+1 < arr.Len(); i += 2 {
				keyMatch := false
				if s, ok := resolvePDFString(r, arr.At(i)); ok && s == targetName {
					keyMatch = true
				}
				data, matched, err := readMatchingFilespec(r, arr.At(i+1), targetName)
				if err != nil {
					return nil, false, err
				}
				if matched {
					return data, true, nil
				}
				if keyMatch {
					// If tree key matched even though filespec /F differed, still extract it.
					if d, err := readFilespecStream(r, arr.At(i+1)); err == nil {
						return d, true, nil
					}
				}
			}
		}
	}

	if kidsObj := node.Get("Kids"); kidsObj != nil {
		resolved, err := r.ResolveObject(kidsObj)
		if err != nil {
			return nil, false, fmt.Errorf("pdf: resolve EmbeddedFiles /Kids: %w", err)
		}
		if kids, ok := resolved.(*core.PdfArray); ok {
			for _, kid := range kids.All() {
				kidObj, err := r.ResolveObject(kid)
				if err != nil {
					return nil, false, fmt.Errorf("pdf: resolve EmbeddedFiles kid: %w", err)
				}
				if kidDict, ok := kidObj.(*core.PdfDictionary); ok {
					data, found, err := walkEmbeddedNameTree(r, kidDict, targetName)
					if err != nil || found {
						return data, found, err
					}
				}
			}
		}
	}

	return nil, false, nil
}

func readMatchingFilespec(r *reader.PdfReader, obj core.PdfObject, targetName string) ([]byte, bool, error) {
	resolved, err := r.ResolveObject(obj)
	if err != nil {
		return nil, false, fmt.Errorf("pdf: resolve filespec: %w", err)
	}
	fsDict, ok := resolved.(*core.PdfDictionary)
	if !ok {
		return nil, false, nil
	}

	uf, _ := resolvePDFString(r, fsDict.Get("UF"))
	f, _ := resolvePDFString(r, fsDict.Get("F"))
	if uf != targetName && f != targetName {
		return nil, false, nil
	}

	data, err := readFilespecStreamFromDict(r, fsDict)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func readFilespecStream(r *reader.PdfReader, obj core.PdfObject) ([]byte, error) {
	resolved, err := r.ResolveObject(obj)
	if err != nil {
		return nil, err
	}
	fsDict, ok := resolved.(*core.PdfDictionary)
	if !ok {
		return nil, fmt.Errorf("pdf: filespec is not a dictionary")
	}
	return readFilespecStreamFromDict(r, fsDict)
}

func readFilespecStreamFromDict(r *reader.PdfReader, fsDict *core.PdfDictionary) ([]byte, error) {
	efObj := fsDict.Get("EF")
	if efObj == nil {
		return nil, fmt.Errorf("pdf: filespec missing /EF")
	}
	resolvedEF, err := r.ResolveObject(efObj)
	if err != nil {
		return nil, fmt.Errorf("pdf: resolve /EF: %w", err)
	}
	efDict, ok := resolvedEF.(*core.PdfDictionary)
	if !ok {
		return nil, fmt.Errorf("pdf: /EF is not a dictionary")
	}

	streamRef := efDict.Get("UF")
	if streamRef == nil {
		streamRef = efDict.Get("F")
	}
	if streamRef == nil {
		return nil, fmt.Errorf("pdf: /EF missing /F and /UF stream")
	}

	streamObj, err := r.ResolveObject(streamRef)
	if err != nil {
		return nil, fmt.Errorf("pdf: resolve embedded file stream: %w", err)
	}
	stream, ok := streamObj.(*core.PdfStream)
	if !ok {
		return nil, fmt.Errorf("pdf: embedded file is not a stream (%T)", streamObj)
	}
	return stream.Data, nil
}

func resolvePDFString(r *reader.PdfReader, obj core.PdfObject) (string, bool) {
	if obj == nil {
		return "", false
	}
	if resolved, err := r.ResolveObject(obj); err == nil {
		obj = resolved
	}
	if s, ok := obj.(*core.PdfString); ok {
		return s.TextString(), true
	}
	return "", false
}

func verifyXMPHMAC(r *reader.PdfReader, rawAttach, canonicalAttach, secret []byte, log *slog.Logger) error {
	catalog := r.Catalog()
	if catalog == nil {
		return fmt.Errorf("pdf: missing PDF catalog for HMAC verification")
	}
	metaObj := catalog.Get("Metadata")
	if metaObj == nil {
		return fmt.Errorf("pdf: PDF missing /Metadata XMP stream for HMAC verification")
	}
	resolved, err := r.ResolveObject(metaObj)
	if err != nil {
		return fmt.Errorf("pdf: resolve /Metadata: %w", err)
	}
	stream, ok := resolved.(*core.PdfStream)
	if !ok {
		return fmt.Errorf("pdf: /Metadata is not a stream")
	}

	hmacHex, found, err := parseXMPHMAC(stream.Data)
	if err != nil {
		return fmt.Errorf("pdf: parse XMP metadata: %w", err)
	}
	if !found || hmacHex == "" {
		return fmt.Errorf("pdf: XMP metadata missing %s:%s", xmpPrefix, xmpHMACProperty)
	}

	gotMAC, err := hex.DecodeString(strings.TrimSpace(hmacHex))
	if err != nil || len(gotMAC) != sha256.Size {
		return fmt.Errorf("pdf: invalid XMP %s:%s hex value", xmpPrefix, xmpHMACProperty)
	}

	// Verify against canonical JSON (and accept raw attachment bytes if already canonical).
	wantCanonical := hmac.New(sha256.New, secret)
	wantCanonical.Write(canonicalAttach)
	if hmac.Equal(gotMAC, wantCanonical.Sum(nil)) {
		log.Debug("pdf: verified XMP payload HMAC")
		return nil
	}
	if !bytes.Equal(rawAttach, canonicalAttach) {
		wantRaw := hmac.New(sha256.New, secret)
		wantRaw.Write(rawAttach)
		if hmac.Equal(gotMAC, wantRaw.Sum(nil)) {
			log.Debug("pdf: verified XMP payload HMAC")
			return nil
		}
	}
	return fmt.Errorf("pdf: HMAC mismatch for embedded JSON payload")
}

func parseXMPHMAC(xmpData []byte) (string, bool, error) {
	dec := xml.NewDecoder(bytes.NewReader(xmpData))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local == xmpHMACProperty && se.Name.Space == xmpNamespace {
			var val string
			if err := dec.DecodeElement(&val, &se); err != nil {
				return "", false, err
			}
			return val, true, nil
		}
	}
}

type destAnchor struct {
	JSONKey string
	Page    int
	TopY    float64
}

type cellRect struct {
	x, y, w, h float64
}

func extractVisualFields(r *reader.PdfReader, opts *ExtractOptions, log *slog.Logger) (fields []VisualField, usedDests, usedFieldMap bool, err error) {
	var anchorsByPage map[int][]destAnchor
	if !opts.IgnoreDests {
		pageObjToIdx := buildPageIndexMap(r)
		anchors := extractDestAnchors(r, pageObjToIdx)
		log.Debug("pdf: loaded /Dests anchors", "anchors", len(anchors))
		if len(anchors) > 0 {
			anchorsByPage = make(map[int][]destAnchor)
			for _, a := range anchors {
				anchorsByPage[a.Page] = append(anchorsByPage[a.Page], a)
			}
		}
	}

	fieldMap := parseTemplateFieldMap(opts.TemplateHTML, log)
	for k, v := range opts.FieldMap {
		fieldMap[k] = v
	}
	if len(fieldMap) > 0 {
		log.Debug("pdf: loaded fallback field map", "entries", len(fieldMap))
	}

	for pIdx := 0; pIdx < r.PageCount(); pIdx++ {
		page, perr := r.Page(pIdx)
		if perr != nil {
			return nil, false, false, fmt.Errorf("pdf: page %d: %w", pIdx, perr)
		}
		paths, perr := page.PathOps()
		if perr != nil {
			return nil, false, false, fmt.Errorf("pdf: page %d paths: %w", pIdx, perr)
		}
		spans, perr := page.TextSpans()
		if perr != nil {
			return nil, false, false, fmt.Errorf("pdf: page %d spans: %w", pIdx, perr)
		}

		rects := collectCellRects(paths)
		rows := groupRectsIntoRows(rects)
		log.Debug("pdf: scanned page visual geometry",
			"page", pIdx,
			"filled_rects", len(rects),
			"rows", len(rows),
			"spans", len(spans),
		)
		pageAnchors := anchorsByPage[pIdx]

		for _, row := range rows {
			codeCell, labelCell, valueCell, ok := findContiguousFormTriple(row, spans)
			if !ok {
				continue
			}
			code := extractCellText(spans, codeCell)
			if !fieldCodeRe.MatchString(code) {
				continue
			}
			label := extractCellText(spans, labelCell)
			value := extractCellText(spans, valueCell)

			jsonKey := ""
			if matched, ok := matchDestAnchor(pageAnchors, codeCell.y, codeCell.h); ok {
				jsonKey = matched
				usedDests = true
			} else if mapped, ok := fieldMap[code]; ok && mapped != "" {
				jsonKey = mapped
				usedFieldMap = true
			}

			log.Debug("pdf: extracted visual field",
				"page", pIdx,
				"code", code,
				"json_key", jsonKey,
				"label", label,
				"value", value,
			)

			fields = append(fields, VisualField{
				Code:    code,
				Label:   label,
				Value:   value,
				JSONKey: jsonKey,
				Page:    pIdx,
			})
		}
	}

	return fields, usedDests, usedFieldMap, nil
}

func buildPageIndexMap(r *reader.PdfReader) map[int]int {
	out := make(map[int]int, r.PageCount())
	catalog := r.Catalog()
	if catalog == nil {
		return out
	}
	pagesRef := catalog.Get("Pages")
	if pagesRef == nil {
		return out
	}

	pageIdx := 0
	var walk func(core.PdfObject, map[int]bool)
	walk = func(obj core.PdfObject, visited map[int]bool) {
		var objNum int
		if ref, ok := obj.(*core.PdfIndirectReference); ok {
			objNum = ref.Num()
			if visited[objNum] {
				return
			}
			visited[objNum] = true
			defer delete(visited, objNum)
		}
		resolved, err := r.ResolveObject(obj)
		if err != nil {
			return
		}
		dict, ok := resolved.(*core.PdfDictionary)
		if !ok {
			return
		}
		if t, ok := dict.Get("Type").(*core.PdfName); ok && t.Value == "Page" {
			if objNum > 0 {
				out[objNum] = pageIdx
			}
			pageIdx++
			return
		}
		kidsObj := dict.Get("Kids")
		if kidsObj == nil {
			return
		}
		kidsResolved, err := r.ResolveObject(kidsObj)
		if err != nil {
			return
		}
		kids, ok := kidsResolved.(*core.PdfArray)
		if !ok {
			return
		}
		for _, kid := range kids.All() {
			walk(kid, visited)
		}
	}
	walk(pagesRef, make(map[int]bool))
	return out
}

func extractDestAnchors(r *reader.PdfReader, pageObjToIdx map[int]int) []destAnchor {
	catalog := r.Catalog()
	if catalog == nil {
		return nil
	}
	destsObj := catalog.Get("Dests")
	if destsObj == nil {
		return nil
	}
	resolved, err := r.ResolveObject(destsObj)
	if err != nil {
		return nil
	}
	destsDict, ok := resolved.(*core.PdfDictionary)
	if !ok {
		return nil
	}

	var anchors []destAnchor
	for key, val := range destsDict.All() {
		if !strings.HasPrefix(key, destAnchorPrefix) {
			continue
		}
		arr := resolveDestArray(r, val)
		if arr == nil || arr.Len() < 2 {
			continue
		}
		pageIdx, ok := resolvePageIndex(r, arr.At(0), pageObjToIdx)
		if !ok {
			continue
		}
		topY, ok := extractDestTopY(r, arr)
		if !ok {
			continue
		}
		anchors = append(anchors, destAnchor{
			JSONKey: strings.TrimPrefix(key, destAnchorPrefix),
			Page:    pageIdx,
			TopY:    topY,
		})
	}
	return anchors
}

func resolveDestArray(r *reader.PdfReader, val core.PdfObject) *core.PdfArray {
	resolved, err := r.ResolveObject(val)
	if err != nil {
		return nil
	}
	if arr, ok := resolved.(*core.PdfArray); ok {
		return arr
	}
	if dict, ok := resolved.(*core.PdfDictionary); ok {
		if dVal := dict.Get("D"); dVal != nil {
			if dRes, err := r.ResolveObject(dVal); err == nil {
				if arr, ok := dRes.(*core.PdfArray); ok {
					return arr
				}
			}
		}
	}
	return nil
}

func resolvePageIndex(r *reader.PdfReader, pageObj core.PdfObject, pageObjToIdx map[int]int) (int, bool) {
	if ref, ok := pageObj.(*core.PdfIndirectReference); ok {
		if idx, found := pageObjToIdx[ref.Num()]; found {
			return idx, true
		}
	}
	resolved, err := r.ResolveObject(pageObj)
	if err != nil {
		return 0, false
	}
	dict, ok := resolved.(*core.PdfDictionary)
	if !ok {
		return 0, false
	}
	for i := 0; i < r.PageCount(); i++ {
		p, err := r.Page(i)
		if err == nil && p.Dict() == dict {
			return i, true
		}
	}
	return 0, false
}

func extractDestTopY(r *reader.PdfReader, arr *core.PdfArray) (float64, bool) {
	fitObj, err := r.ResolveObject(arr.At(1))
	if err != nil {
		return 0, false
	}
	fitName, ok := fitObj.(*core.PdfName)
	if !ok {
		return 0, false
	}
	var topObj core.PdfObject
	switch fitName.Value {
	case "XYZ":
		if arr.Len() < 4 {
			return 0, false
		}
		topObj = arr.At(3)
	case "FitH", "FitBH":
		if arr.Len() < 3 {
			return 0, false
		}
		topObj = arr.At(2)
	case "FitR":
		if arr.Len() < 6 {
			return 0, false
		}
		topObj = arr.At(5)
	default:
		return 0, false
	}
	resolved, err := r.ResolveObject(topObj)
	if err != nil {
		return 0, false
	}
	num, ok := resolved.(*core.PdfNumber)
	if !ok {
		return 0, false
	}
	return num.FloatValue(), true
}

func collectCellRects(paths []reader.PathOp) []cellRect {
	var rects []cellRect
	for _, op := range paths {
		if op.Type != reader.PathRect || op.Painted != reader.PaintFill || len(op.Points) < 2 {
			continue
		}
		x, y := op.Points[0][0], op.Points[0][1]
		w, h := op.Points[1][0], op.Points[1][1]
		if w < 0 {
			x += w
			w = -w
		}
		if h < 0 {
			y += h
			h = -h
		}
		if w < 5 || h < 5 || h > 400 {
			continue
		}
		cand := cellRect{x: x, y: y, w: w, h: h}
		dup := false
		for _, prev := range rects {
			if math.Abs(prev.x-cand.x) <= 1.0 &&
				math.Abs(prev.y-cand.y) <= 1.0 &&
				math.Abs(prev.w-cand.w) <= 1.0 &&
				math.Abs(prev.h-cand.h) <= 1.0 {
				dup = true
				break
			}
		}
		if !dup {
			rects = append(rects, cand)
		}
	}
	return rects
}

func groupRectsIntoRows(rects []cellRect) [][]cellRect {
	if len(rects) == 0 {
		return nil
	}
	sorted := make([]cellRect, len(rects))
	copy(sorted, rects)
	sort.Slice(sorted, func(i, j int) bool {
		if math.Abs(sorted[i].y-sorted[j].y) > 2.0 {
			return sorted[i].y > sorted[j].y
		}
		return sorted[i].x < sorted[j].x
	})

	var rows [][]cellRect
	for _, r := range sorted {
		placed := false
		for idx := range rows {
			anchor := rows[idx][0]
			if math.Abs(anchor.y-r.y) <= 2.0 && math.Abs(anchor.h-r.h) <= 2.0 {
				rows[idx] = append(rows[idx], r)
				placed = true
				break
			}
		}
		if !placed {
			rows = append(rows, []cellRect{r})
		}
	}

	for idx := range rows {
		sort.Slice(rows[idx], func(i, j int) bool {
			return rows[idx][i].x < rows[idx][j].x
		})
	}
	return rows
}

func findContiguousFormTriple(row []cellRect, spans []reader.TextSpan) (c0, c1, c2 cellRect, ok bool) {
	if len(row) < 3 {
		return cellRect{}, cellRect{}, cellRect{}, false
	}
	for i := 0; i <= len(row)-3; i++ {
		a, b, c := row[i], row[i+1], row[i+2]
		if math.Abs((a.x+a.w)-b.x) <= 2.0 && math.Abs((b.x+b.w)-c.x) <= 2.0 {
			if fieldCodeRe.MatchString(extractCellText(spans, a)) {
				return a, b, c, true
			}
		}
	}
	return cellRect{}, cellRect{}, cellRect{}, false
}

func matchDestAnchor(anchors []destAnchor, rowY, rowH float64) (string, bool) {
	if len(anchors) == 0 {
		return "", false
	}
	rowTop := rowY + rowH
	bestKey := ""
	bestDist := math.Inf(1)
	for _, a := range anchors {
		if a.TopY < rowY-3.0 || a.TopY > rowTop+3.0 {
			continue
		}
		dist := math.Abs(rowTop - a.TopY)
		if dist < bestDist {
			bestDist = dist
			bestKey = a.JSONKey
		}
	}
	return bestKey, bestKey != ""
}

func extractCellText(spans []reader.TextSpan, rect cellRect) string {
	var inCell []reader.TextSpan
	for _, sp := range spans {
		if !sp.Visible {
			continue
		}
		midX := sp.X + sp.Width/2.0
		if sp.Width == 0 {
			midX = sp.X
		}
		if midX < rect.x-1.0 || midX > rect.x+rect.w+1.0 {
			continue
		}
		if sp.Y < rect.y-1.5 || sp.Y > rect.y+rect.h+1.5 {
			continue
		}
		inCell = append(inCell, sp)
	}
	if len(inCell) == 0 {
		return ""
	}

	sort.Slice(inCell, func(i, j int) bool {
		if inCell[i].Y != inCell[j].Y {
			return inCell[i].Y > inCell[j].Y
		}
		return inCell[i].X < inCell[j].X
	})

	type visualLine struct {
		anchorY float64
		maxH    float64
		spans   []reader.TextSpan
	}
	var lines []visualLine
	for _, sp := range inCell {
		spH := sp.Height
		if spH <= 0 {
			spH = 12
		}
		if len(lines) == 0 {
			lines = append(lines, visualLine{anchorY: sp.Y, maxH: spH, spans: []reader.TextSpan{sp}})
			continue
		}
		last := &lines[len(lines)-1]
		lineH := math.Max(last.maxH, spH)
		if math.Abs(last.anchorY-sp.Y) <= lineH*0.6 {
			last.spans = append(last.spans, sp)
			if spH > last.maxH {
				last.maxH = spH
			}
		} else {
			lines = append(lines, visualLine{anchorY: sp.Y, maxH: spH, spans: []reader.TextSpan{sp}})
		}
	}

	renderedLines := make([]string, 0, len(lines))
	for _, line := range lines {
		sort.Slice(line.spans, func(i, j int) bool {
			return line.spans[i].X < line.spans[j].X
		})

		var sb strings.Builder
		prevEndX := 0.0
		hasPrev := false
		for _, sp := range line.spans {
			if sp.Text == "" {
				continue
			}
			if hasPrev {
				h := sp.Height
				if h <= 0 {
					h = 12
				}
				threshold := h * 0.15
				// Type0 Identity-H fonts in folio/reader can report defaultW (1000 = 1.0*h)
				// as SpaceWidth because SpaceWidth() looks up CID 32 instead of Unicode ' '.
				if sp.SpaceWidth > 0 && sp.SpaceWidth < h*0.6 {
					threshold = sp.SpaceWidth * 0.4
				}
				gap := sp.X - prevEndX
				if gap > threshold {
					cur := sb.String()
					if !strings.HasSuffix(cur, " ") && !strings.HasPrefix(sp.Text, " ") {
						sb.WriteByte(' ')
					}
				}
			}
			sb.WriteString(sp.Text)
			prevEndX = sp.X + sp.Width
			hasPrev = true
		}
		trimmed := strings.TrimSpace(sb.String())
		if trimmed != "" {
			renderedLines = append(renderedLines, trimmed)
		}
	}

	return strings.TrimSpace(strings.Join(renderedLines, " "))
}
