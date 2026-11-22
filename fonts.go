// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

// FontConfig specifies filesystem paths to static TrueType/OpenType fonts
// embedded into generated PDFs for PDF/A conformance and Unicode support.
type FontConfig struct {
	Regular    string
	Medium     string
	Bold       string
	Italic     string
	BoldItalic string
}

var fontFamilyDeclRe = regexp.MustCompile(`(?i)font-family\s*:\s*([^;}{]+)`)

var genericFontFamilies = map[string]bool{
	"sans-serif":  true,
	"serif":       true,
	"monospace":   true,
	"ui-monospace": true,
	"system-ui":   true,
	"cursive":     true,
	"fantasy":     true,
	"inherit":     true,
	"initial":     true,
	"unset":       true,
}

func resolveFontConfig(override FontConfig, log *slog.Logger) (FontConfig, error) {
	log = resolveLogger(log)
	if override.Regular != "" {
		if _, err := os.Stat(override.Regular); err != nil {
			return FontConfig{}, fmt.Errorf("pdf: font Regular %q: %w", override.Regular, err)
		}
		resolved := fillFontVariants(override)
		log.Debug("pdf: resolved font config from caller override",
			"regular", resolved.Regular,
			"medium", resolved.Medium,
			"bold", resolved.Bold,
			"italic", resolved.Italic,
			"bold_italic", resolved.BoldItalic,
		)
		return resolved, nil
	}

	discovered, err := discoverSystemFonts()
	if err != nil {
		return FontConfig{}, err
	}
	mergedOverride := false
	if override.Medium != "" {
		discovered.Medium = override.Medium
		mergedOverride = true
	}
	if override.Bold != "" {
		discovered.Bold = override.Bold
		mergedOverride = true
	}
	if override.Italic != "" {
		discovered.Italic = override.Italic
		mergedOverride = true
	}
	if override.BoldItalic != "" {
		discovered.BoldItalic = override.BoldItalic
		mergedOverride = true
	}
	resolved := fillFontVariants(discovered)
	log.Debug("pdf: resolved font config from system auto-discovery",
		"variant_overrides", mergedOverride,
		"regular", resolved.Regular,
		"medium", resolved.Medium,
		"bold", resolved.Bold,
		"italic", resolved.Italic,
		"bold_italic", resolved.BoldItalic,
	)
	return resolved, nil
}

func fillFontVariants(c FontConfig) FontConfig {
	if c.Medium == "" {
		c.Medium = c.Regular
	}
	if c.Bold == "" {
		c.Bold = c.Regular
	}
	if c.Italic == "" {
		c.Italic = c.Regular
	}
	if c.BoldItalic == "" {
		c.BoldItalic = c.Regular
	}
	return c
}

func discoverSystemFonts() (FontConfig, error) {
	candidates := []FontConfig{
		// Ubuntu static TTF family (preferred on Ubuntu/Debian desktops).
		{
			Regular:    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
			Medium:     "/usr/share/fonts/truetype/ubuntu/Ubuntu-M.ttf",
			Bold:       "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
			Italic:     "/usr/share/fonts/truetype/ubuntu/Ubuntu-RI.ttf",
			BoldItalic: "/usr/share/fonts/truetype/ubuntu/Ubuntu-BI.ttf",
		},
		// DejaVu Sans (Linux).
		{
			Regular: "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
			Bold:    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
		},
		{
			Regular: "/usr/share/fonts/dejavu/DejaVuSans.ttf",
			Bold:    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
		},
		// Liberation Sans / Noto Sans (Linux).
		{
			Regular:    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
			Bold:       "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
			Italic:     "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf",
			BoldItalic: "/usr/share/fonts/truetype/liberation/LiberationSans-BoldItalic.ttf",
		},
		{
			Regular:    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
			Bold:       "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
			Italic:     "/usr/share/fonts/truetype/noto/NotoSans-Italic.ttf",
			BoldItalic: "/usr/share/fonts/truetype/noto/NotoSans-BoldItalic.ttf",
		},
		// macOS.
		{
			Regular:    "/System/Library/Fonts/Supplemental/Arial.ttf",
			Bold:       "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
			Italic:     "/System/Library/Fonts/Supplemental/Arial Italic.ttf",
			BoldItalic: "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf",
		},
		{
			Regular:    "/System/Library/Fonts/Supplemental/Verdana.ttf",
			Bold:       "/System/Library/Fonts/Supplemental/Verdana Bold.ttf",
			Italic:     "/System/Library/Fonts/Supplemental/Verdana Italic.ttf",
			BoldItalic: "/System/Library/Fonts/Supplemental/Verdana Bold Italic.ttf",
		},
		// Windows.
		{
			Regular:    `C:\Windows\Fonts\arial.ttf`,
			Bold:       `C:\Windows\Fonts\arialbd.ttf`,
			Italic:     `C:\Windows\Fonts\ariali.ttf`,
			BoldItalic: `C:\Windows\Fonts\arialbi.ttf`,
		},
		{
			Regular:    `C:\Windows\Fonts\segoeui.ttf`,
			Bold:       `C:\Windows\Fonts\segoeuib.ttf`,
			Italic:     `C:\Windows\Fonts\segoeuii.ttf`,
			BoldItalic: `C:\Windows\Fonts\segoeuiz.ttf`,
		},
	}

	for _, cand := range candidates {
		if !fileExists(cand.Regular) {
			continue
		}
		out := FontConfig{Regular: cand.Regular}
		if fileExists(cand.Medium) {
			out.Medium = cand.Medium
		}
		if fileExists(cand.Bold) {
			out.Bold = cand.Bold
		}
		if fileExists(cand.Italic) {
			out.Italic = cand.Italic
		}
		if fileExists(cand.BoldItalic) {
			out.BoldItalic = cand.BoldItalic
		}
		return fillFontVariants(out), nil
	}

	return FontConfig{}, fmt.Errorf("pdf: no suitable system TrueType font found; supply PDFOptions.Fonts")
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func injectFontFacesCSS(htmlStr string, fonts FontConfig, log *slog.Logger) string {
	if fonts.Regular == "" {
		return htmlStr
	}
	log = resolveLogger(log)
	fonts = fillFontVariants(fonts)
	families := collectPrimaryFontFamilies(htmlStr)

	var css strings.Builder
	css.WriteString("<style>\n")
	for _, family := range families {
		writeFontFaceBlock(&css, family, 400, "normal", fonts.Regular)
		writeFontFaceBlock(&css, family, 500, "normal", fonts.Medium)
		writeFontFaceBlock(&css, family, 700, "normal", fonts.Bold)
		writeFontFaceBlock(&css, family, 400, "italic", fonts.Italic)
		writeFontFaceBlock(&css, family, 700, "italic", fonts.BoldItalic)
	}
	css.WriteString("</style>\n")

	log.Debug("pdf: injected @font-face CSS", "families", families, "regular", fonts.Regular)

	if idx := findCaseInsensitive(htmlStr, "</head>"); idx >= 0 {
		return htmlStr[:idx] + css.String() + htmlStr[idx:]
	}
	return css.String() + htmlStr
}

func collectPrimaryFontFamilies(htmlStr string) []string {
	seen := make(map[string]bool)
	var families []string

	addFamily := func(raw string) {
		first := raw
		if idx := strings.IndexByte(first, ','); idx >= 0 {
			first = first[:idx]
		}
		first = strings.TrimSpace(first)
		first = strings.Trim(first, `"'`)
		if first == "" {
			return
		}
		lower := strings.ToLower(first)
		if genericFontFamilies[lower] || seen[lower] {
			return
		}
		seen[lower] = true
		families = append(families, first)
	}

	lowerHTML := strings.ToLower(htmlStr)
	pos := 0
	for {
		start := strings.Index(lowerHTML[pos:], "<style")
		if start < 0 {
			break
		}
		gt := strings.IndexByte(lowerHTML[pos+start:], '>')
		if gt < 0 {
			break
		}
		bodyStart := pos + start + gt + 1
		endRel := strings.Index(lowerHTML[bodyStart:], "</style>")
		if endRel < 0 {
			break
		}
		styleBody := htmlStr[bodyStart : bodyStart+endRel]
		for _, m := range fontFamilyDeclRe.FindAllStringSubmatch(styleBody, -1) {
			if len(m) >= 2 {
				addFamily(m[1])
			}
		}
		pos = bodyStart + endRel + len("</style>")
	}

	if len(families) == 0 {
		addFamily("DocSans")
	}
	// Ensure default fallback family "helvetica" (used by folio when an element
	// or @page margin box omits font-family) also maps to an embedded TTF.
	addFamily("helvetica")
	return families
}

func writeFontFaceBlock(sb *strings.Builder, family string, weight int, style, path string) {
	escapedPath := strings.ReplaceAll(path, `'`, `\'`)
	fmt.Fprintf(sb,
		"@font-face { font-family: '%s'; font-weight: %d; font-style: %s; src: url('%s'); }\n",
		family, weight, style, escapedPath,
	)
}

func findCaseInsensitive(haystack, needle string) int {
	return strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
}
