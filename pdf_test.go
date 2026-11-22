// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/carlos7ags/folio/core"
	"github.com/carlos7ags/folio/reader"
	"github.com/carlos7ags/folio/sign"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

func TestRenderHTML(t *testing.T) {
	origTmpl := string(loadFixture(t, "template.html"))
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	for _, tc := range []struct {
		name string
		tmpl string
	}{
		{"original_template.html", origTmpl},
		{"pdf_template_pdf.html", pdfTmpl},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rendered, err := RenderHTML(tc.tmpl, sampleJSON)
			if err != nil {
				t.Fatalf("RenderHTML failed: %v", err)
			}
			if strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
				t.Fatalf("unreplaced placeholders remain in rendered HTML")
			}
			if !strings.Contains(rendered, "Soluciones &amp; Servicios Cloud S.L.") {
				t.Errorf("expected HTML-escaped company name in rendered output")
			}
			if !strings.Contains(rendered, "María") {
				t.Errorf("expected UTF-8 name in rendered output")
			}
		})
	}

	// Missing key should error by default.
	if _, err := RenderHTML(pdfTmpl, []byte(`{"date":"2026-03-15"}`)); err == nil {
		t.Fatalf("expected error for missing JSON keys, got nil")
	}

	// AllowMissing replaces missing keys with empty string.
	partial, err := RenderHTMLWithOptions(pdfTmpl, []byte(`{"date":"2026-03-15"}`), RenderOptions{AllowMissing: true})
	if err != nil {
		t.Fatalf("RenderHTMLWithOptions(AllowMissing) failed: %v", err)
	}
	if strings.Contains(partial, "{{") || strings.Contains(partial, "}}") {
		t.Fatalf("unreplaced placeholders remain with AllowMissing")
	}

	// Placeholders & field map.
	placeholders := TemplatePlaceholders(pdfTmpl)
	if len(placeholders) != 14 {
		t.Fatalf("TemplatePlaceholders count = %d, want 14 (%v)", len(placeholders), placeholders)
	}

	fmap := ParseTemplateFieldMap(pdfTmpl)
	if len(fmap) != 14 {
		t.Fatalf("ParseTemplateFieldMap count = %d, want 14 (%v)", len(fmap), fmap)
	}
	wantPairs := map[string]string{
		"0.1": "date",
		"1.1": "legal_rep.name",
		"1.2": "legal_rep.surname",
		"1.3": "legal_rep.id_number",
		"1.4": "legal_rep.email",
		"2.1": "company.legal_name",
		"2.2": "company.registered_address",
		"2.3": "company.country_code",
		"2.4": "company.tax_id",
		"3.1": "account_admin.name",
		"3.2": "account_admin.surname",
		"3.3": "account_admin.id_number",
		"3.4": "account_admin.postal_address",
		"3.5": "account_admin.email",
	}
	for code, wantKey := range wantPairs {
		if fmap[code] != wantKey {
			t.Errorf("fmap[%q] = %q, want %q", code, fmap[code], wantKey)
		}
	}
}

func TestRoundTrip_PDFA3B_AndCrossCheck(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	pdfBytes, err := GeneratePDF(rendered, sampleJSON, nil)
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}

	// Write to a file so the user can check that it reads correctly
	// and the visual fields show correctly
	err = os.WriteFile("test.pdf", pdfBytes, 0644)
	if err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	// Verify PDF/A-3B catalog structures.
	r, err := reader.Parse(pdfBytes)
	if err != nil {
		t.Fatalf("reader.Parse: %v", err)
	}
	cat := r.Catalog()
	if cat.Get("OutputIntents") == nil {
		t.Errorf("PDF missing /OutputIntents")
	}
	if cat.Get("AF") == nil {
		t.Errorf("PDF missing /AF")
	}
	metaObj := cat.Get("Metadata")
	if metaObj == nil {
		t.Fatalf("PDF missing /Metadata")
	}
	resolvedMeta, err := r.ResolveObject(metaObj)
	if err != nil {
		t.Fatalf("resolve /Metadata: %v", err)
	}
	metaStream, ok := resolvedMeta.(*core.PdfStream)
	if !ok {
		t.Fatalf("/Metadata is %T, want *core.PdfStream", resolvedMeta)
	}
	xmp := string(metaStream.Data)
	if !strings.Contains(xmp, "<pdfaid:part>3</pdfaid:part>") ||
		!strings.Contains(xmp, "<pdfaid:conformance>B</pdfaid:conformance>") {
		t.Errorf("XMP missing PDF/A-3B identification:\n%s", xmp)
	}

	res, err := Extract(pdfBytes, nil)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.Source != SourceAttachment {
		t.Errorf("Source = %q, want %q", res.Source, SourceAttachment)
	}
	if len(res.VisualFields) != 14 {
		t.Errorf("VisualFields count = %d, want 14", len(res.VisualFields))
	}
	if len(res.VisualMismatches) != 0 {
		t.Errorf("unexpected VisualMismatches: %+v", res.VisualMismatches)
	}
	for _, vf := range res.VisualFields {
		if vf.Label == "" || vf.JSONKey == "" {
			t.Errorf("incomplete VisualField metadata: %+v", vf)
		}
		if vf.JSONKey == "account_admin.id_number" && vf.Value != "" {
			t.Errorf("expected empty account_admin.id_number, got %q", vf.Value)
		}
	}

	extracted, err := ExtractJSON(pdfBytes)
	if err != nil {
		t.Fatalf("ExtractJSON: %v", err)
	}
	cmp, err := CompareJSON(sampleJSON, extracted)
	if err != nil {
		t.Fatalf("CompareJSON: %v", err)
	}
	if !cmp.Equal {
		t.Fatalf("JSON mismatch: %+v", cmp)
	}
}

func TestExtract_VisualOnly_WithDests(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	// Case 1: PDF generated with attachment disabled.
	pdfNoAttach, err := GeneratePDF(rendered, sampleJSON, &PDFOptions{DisableAttachment: true})
	if err != nil {
		t.Fatalf("GeneratePDF(DisableAttachment): %v", err)
	}
	res1, err := Extract(pdfNoAttach, nil)
	if err != nil {
		t.Fatalf("Extract(no attach): %v", err)
	}
	if res1.Source != SourceVisualDests {
		t.Errorf("Source = %q, want %q", res1.Source, SourceVisualDests)
	}
	if cmp, err := CompareJSON(sampleJSON, res1.JSON); err != nil || !cmp.Equal {
		t.Fatalf("visual dests JSON mismatch (err=%v): %+v", err, cmp)
	}

	// Case 2: Full PDF/A-3B forced to visual-only extraction without template.
	fullPDF, err := GeneratePDF(rendered, sampleJSON, nil)
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	res2, err := Extract(fullPDF, &ExtractOptions{VisualOnly: true})
	if err != nil {
		t.Fatalf("Extract(VisualOnly): %v", err)
	}
	if res2.Source != SourceVisualDests {
		t.Errorf("Source = %q, want %q", res2.Source, SourceVisualDests)
	}
	if cmp, err := CompareJSON(sampleJSON, res2.JSON); err != nil || !cmp.Equal {
		t.Fatalf("VisualOnly JSON mismatch (err=%v): %+v", err, cmp)
	}
}

func TestExtract_FlattenedPDF_FieldCodesFallback(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	fullPDF, err := GeneratePDF(rendered, sampleJSON, nil)
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}

	// Simulate destructive Print-to-PDF / cloud flattener via reader.Merge,
	// which drops /AF, /Names/EmbeddedFiles, /Dests, and /Metadata.
	r, err := reader.Parse(fullPDF)
	if err != nil {
		t.Fatalf("reader.Parse: %v", err)
	}
	mod, err := reader.Merge(r)
	if err != nil {
		t.Fatalf("reader.Merge: %v", err)
	}
	var buf bytes.Buffer
	if _, err := mod.WriteTo(&buf); err != nil {
		t.Fatalf("mod.WriteTo: %v", err)
	}
	flattenedPDF := buf.Bytes()

	res, err := Extract(flattenedPDF, &ExtractOptions{TemplateHTML: pdfTmpl})
	if err != nil {
		t.Fatalf("Extract(flattened): %v", err)
	}
	if res.Source != SourceVisualFieldMap {
		t.Errorf("Source = %q, want %q", res.Source, SourceVisualFieldMap)
	}
	if cmp, err := CompareJSON(sampleJSON, res.JSON); err != nil || !cmp.Equal {
		t.Fatalf("flattened JSON mismatch (err=%v): %+v", err, cmp)
	}

	// Without TemplateHTML or FieldMap, falls back cleanly to SourceVisualCodes.
	resCodes, err := Extract(flattenedPDF, nil)
	if err != nil {
		t.Fatalf("Extract(flattened, no template): %v", err)
	}
	if resCodes.Source != SourceVisualCodes {
		t.Errorf("Source = %q, want %q", resCodes.Source, SourceVisualCodes)
	}
	codeObj, err := decodeJSONObject(resCodes.JSON)
	if err != nil {
		t.Fatalf("decode code JSON: %v", err)
	}
	if codeObj["2.4"] != "ESB87654321" {
		t.Errorf("codeObj[2.4] = %v, want ESB87654321", codeObj["2.4"])
	}
}

func TestExtract_DetectsTampering(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	tamperedJSON := strings.Replace(string(sampleJSON), "ESB87654321", "ESB99999999", 1)
	pdfBytes, err := GeneratePDF(rendered, []byte(tamperedJSON), nil)
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}

	if _, err := ExtractJSON(pdfBytes); err == nil {
		t.Fatalf("expected ExtractJSON to fail on attachment/visual mismatch")
	}

	res, err := Extract(pdfBytes, nil)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	found := false
	for _, mm := range res.VisualMismatches {
		if mm.Key == "company.tax_id" && mm.Expected == "ESB99999999" && mm.Actual == "ESB87654321" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mismatch on company.tax_id, got %+v", res.VisualMismatches)
	}
}

func TestRoundTrip_PAdES_SignedPDF(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")
	secret := []byte("super-secret-onboarding-key")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	pdfBytes, err := GeneratePDF(rendered, sampleJSON, &PDFOptions{HMACSecret: secret})
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}

	// Verify custom XMP prefix does not collide with Adobe's xmlns:pdf namespace.
	r, err := reader.Parse(pdfBytes)
	if err != nil {
		t.Fatalf("reader.Parse: %v", err)
	}
	resolvedMeta, err := r.ResolveObject(r.Catalog().Get("Metadata"))
	if err != nil {
		t.Fatalf("resolve /Metadata: %v", err)
	}
	xmp := string(resolvedMeta.(*core.PdfStream).Data)
	if !strings.Contains(xmp, `xmlns:pdf="http://ns.adobe.com/pdf/1.3/"`) {
		t.Errorf("XMP missing Adobe pdf namespace")
	}
	if !strings.Contains(xmp, `xmlns:pdfdata="`+xmpNamespace+`"`) || !strings.Contains(xmp, `<pdfdata:PayloadHMAC>`) {
		t.Errorf("XMP missing pdfdata:PayloadHMAC:\n%s", xmp)
	}

	cert, signer := makeTestECDSASigner(t)
	signedPDF, err := sign.SignPDF(pdfBytes, sign.Options{
		Signer:      signer,
		Level:       sign.LevelBB,
		Name:        "María García López",
		Reason:      "Onboarding approval",
		Location:    "Madrid",
		SigningTime: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("SignPDF: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	report, err := sign.Verify(signedPDF, sign.VerifyOptions{Roots: roots})
	if err != nil {
		t.Fatalf("sign.Verify: %v", err)
	}
	if len(report.Signatures) != 1 || !report.Signatures[0].OK() {
		t.Fatalf("signature did not verify cleanly: %+v", report.Signatures)
	}

	res, err := Extract(signedPDF, &ExtractOptions{HMACSecret: secret})
	if err != nil {
		t.Fatalf("Extract(signed): %v", err)
	}
	if !res.HMACVerified {
		t.Errorf("expected HMACVerified = true")
	}
	if res.Source != SourceAttachment {
		t.Errorf("Source = %q, want %q", res.Source, SourceAttachment)
	}
	if len(res.VisualMismatches) != 0 {
		t.Errorf("unexpected VisualMismatches: %+v", res.VisualMismatches)
	}
	for _, vf := range res.VisualFields {
		if vf.Label == "" || vf.JSONKey == "" {
			t.Errorf("incomplete VisualField metadata: %+v", vf)
		}
		if vf.JSONKey == "account_admin.id_number" && vf.Value != "" {
			t.Errorf("expected empty account_admin.id_number, got %q", vf.Value)
		}
	}
	if ok, err := EqualJSON(sampleJSON, res.JSON); err != nil || !ok {
		t.Fatalf("signed attachment JSON mismatch (err=%v, ok=%v)", err, ok)
	}

	resVis, err := Extract(signedPDF, &ExtractOptions{VisualOnly: true})
	if err != nil {
		t.Fatalf("Extract(signed, VisualOnly): %v", err)
	}
	if resVis.Source != SourceVisualDests {
		t.Errorf("VisualOnly Source = %q, want %q", resVis.Source, SourceVisualDests)
	}
	if ok, err := EqualJSON(sampleJSON, resVis.JSON); err != nil || !ok {
		t.Fatalf("signed visual JSON mismatch (err=%v, ok=%v)", err, ok)
	}
}

func TestGeneratePDF_HMAC_Mismatch(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")

	rendered, err := RenderHTML(pdfTmpl, sampleJSON)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	pdfWithHMAC, err := GeneratePDF(rendered, sampleJSON, &PDFOptions{
		HMACSecret: []byte("secret-one"),
	})
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	if _, err := Extract(pdfWithHMAC, &ExtractOptions{HMACSecret: []byte("wrong-secret")}); err == nil {
		t.Fatalf("expected error on wrong HMACSecret")
	}

	pdfNoHMAC, err := GeneratePDF(rendered, sampleJSON, nil)
	if err != nil {
		t.Fatalf("GeneratePDF(no HMAC): %v", err)
	}
	if _, err := Extract(pdfNoHMAC, &ExtractOptions{HMACSecret: []byte("secret-one")}); err == nil {
		t.Fatalf("expected error when PDF lacks XMP HMAC")
	}
}

func TestCompareJSON(t *testing.T) {
	a := []byte(`{
		"b": 2,
		"a": { "y": "hello", "x": true }
	}`)
	b := []byte(`{"a":{"x":true,"y":"hello"},"b":2}`)
	cmp, err := CompareJSON(a, b)
	if err != nil {
		t.Fatalf("CompareJSON equal: %v", err)
	}
	if !cmp.Equal || len(cmp.Mismatches) != 0 || len(cmp.MissingKeys) != 0 || len(cmp.ExtraKeys) != 0 {
		t.Fatalf("expected equal JSON, got %+v", cmp)
	}

	c := []byte(`{"a":{"x":false,"z":"extra"},"b":2}`)
	diff, err := CompareJSON(a, c)
	if err != nil {
		t.Fatalf("CompareJSON diff: %v", err)
	}
	if diff.Equal {
		t.Fatalf("expected unequal JSON")
	}
	if len(diff.Mismatches) != 1 || diff.Mismatches[0].Key != "a.x" {
		t.Errorf("Mismatches = %+v, want mismatch on a.x", diff.Mismatches)
	}
	if len(diff.MissingKeys) != 1 || diff.MissingKeys[0] != "a.y" {
		t.Errorf("MissingKeys = %v, want [a.y]", diff.MissingKeys)
	}
	if len(diff.ExtraKeys) != 1 || diff.ExtraKeys[0] != "a.z" {
		t.Errorf("ExtraKeys = %v, want [a.z]", diff.ExtraKeys)
	}
}

func TestDebugLogging(t *testing.T) {
	pdfTmpl := string(loadFixture(t, "template_pdf.html"))
	sampleJSON := loadFixture(t, "sample.json")
	secretStr := "do-not-log-this-hmac-secret-value"
	secret := []byte(secretStr)

	t.Run("per_call_logger", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

		rendered, err := RenderHTMLWithOptions(pdfTmpl, sampleJSON, RenderOptions{Logger: logger})
		if err != nil {
			t.Fatalf("RenderHTMLWithOptions: %v", err)
		}
		pdfBytes, err := GeneratePDF(rendered, sampleJSON, &PDFOptions{
			HMACSecret: secret,
			Logger:     logger,
		})
		if err != nil {
			t.Fatalf("GeneratePDF: %v", err)
		}
		if _, err := Extract(pdfBytes, &ExtractOptions{
			HMACSecret: secret,
			Logger:     logger,
		}); err != nil {
			t.Fatalf("Extract: %v", err)
		}

		logs := buf.String()
		if strings.Contains(logs, secretStr) {
			t.Fatalf("debug logs leaked HMACSecret")
		}
		if strings.Contains(logs, "level=WARN") || strings.Contains(logs, "level=ERROR") {
			t.Fatalf("unexpected WARN/ERROR log entries during clean run:\n%s", logs)
		}

		expectedMsgs := []string{
			"pdf: rendering HTML template",
			"pdf: rendered HTML template",
			"pdf: generating PDF",
			"pdf: resolved font config",
			"pdf: injected @font-face CSS",
			"pdf: prepared HTML for PDF",
			"pdf: converted HTML to layout document",
			"pdf: configured PDF/A-3B conformance",
			"pdf: attached JSON payload to PDF",
			"pdf: generated PDF",
			"pdf: extracting data from PDF",
			"pdf: parsed PDF",
			"pdf: extracted attachment via /AF",
			"pdf: loaded /Dests anchors",
			"pdf: scanned page visual geometry",
			"pdf: extracted visual field",
			"pdf: verified XMP payload HMAC",
			"pdf: completed visual cross-check",
			"pdf: extraction complete",
		}
		for _, msg := range expectedMsgs {
			if !strings.Contains(logs, msg) {
				t.Errorf("missing expected debug log %q in:\n%s", msg, logs)
			}
		}
	})

	t.Run("default_logger_levels", func(t *testing.T) {
		prev := slog.Default()
		t.Cleanup(func() { slog.SetDefault(prev) })

		var debugBuf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&debugBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))

		rendered, err := RenderHTML(pdfTmpl, sampleJSON)
		if err != nil {
			t.Fatalf("RenderHTML: %v", err)
		}
		pdfBytes, err := GeneratePDF(rendered, sampleJSON, nil)
		if err != nil {
			t.Fatalf("GeneratePDF: %v", err)
		}
		extracted, err := ExtractJSON(pdfBytes)
		if err != nil {
			t.Fatalf("ExtractJSON: %v", err)
		}
		if _, err := CompareJSON(sampleJSON, extracted); err != nil {
			t.Fatalf("CompareJSON: %v", err)
		}

		debugLogs := debugBuf.String()
		for _, msg := range []string{
			"pdf: rendering HTML template",
			"pdf: generating PDF",
			"pdf: extracting data from PDF",
			"pdf: compared JSON objects",
		} {
			if !strings.Contains(debugLogs, msg) {
				t.Errorf("default logger at LevelDebug missing %q", msg)
			}
		}

		var infoBuf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&infoBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		if _, err := RenderHTML(pdfTmpl, sampleJSON); err != nil {
			t.Fatalf("RenderHTML(Info): %v", err)
		}
		if _, err := CompareJSON(sampleJSON, extracted); err != nil {
			t.Fatalf("CompareJSON(Info): %v", err)
		}
		if infoBuf.Len() != 0 {
			t.Errorf("expected zero debug output at LevelInfo, got:\n%s", infoBuf.String())
		}
	})
}

func makeTestECDSASigner(t *testing.T) (*x509.Certificate, *sign.LocalSigner) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "PDF Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	signer, err := sign.NewLocalSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return cert, signer
}
