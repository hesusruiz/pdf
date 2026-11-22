// Copyright 2026 The pdf Authors
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// CompareResult summarizes differences between two JSON objects flattened to
// dotted key paths.
type CompareResult struct {
	Equal       bool
	Mismatches  []FieldMismatch
	MissingKeys []string // keys present in expected but absent in actual
	ExtraKeys   []string // keys present in actual but absent in expected
}

// CompareJSON compares expected and actual JSON objects field-by-field across
// all nested dotted paths.
func CompareJSON(expected, actual []byte) (*CompareResult, error) {
	expObj, err := decodeJSONObject(expected)
	if err != nil {
		return nil, fmt.Errorf("expected JSON: %w", err)
	}
	actObj, err := decodeJSONObject(actual)
	if err != nil {
		return nil, fmt.Errorf("actual JSON: %w", err)
	}

	expFlat := flattenJSONObject(expObj)
	actFlat := flattenJSONObject(actObj)

	allKeysMap := make(map[string]bool, len(expFlat)+len(actFlat))
	for k := range expFlat {
		allKeysMap[k] = true
	}
	for k := range actFlat {
		allKeysMap[k] = true
	}

	allKeys := make([]string, 0, len(allKeysMap))
	for k := range allKeysMap {
		allKeys = append(allKeys, k)
	}
	sort.Strings(allKeys)

	res := &CompareResult{Equal: true}
	for _, k := range allKeys {
		ev, eok := expFlat[k]
		av, aok := actFlat[k]
		switch {
		case eok && !aok:
			res.MissingKeys = append(res.MissingKeys, k)
			res.Equal = false
		case !eok && aok:
			res.ExtraKeys = append(res.ExtraKeys, k)
			res.Equal = false
		case ev != av:
			res.Mismatches = append(res.Mismatches, FieldMismatch{
				Key:      k,
				Expected: ev,
				Actual:   av,
			})
			res.Equal = false
		}
	}
	slog.Debug("pdf: compared JSON objects",
		"equal", res.Equal,
		"mismatches", len(res.Mismatches),
		"missing_keys", len(res.MissingKeys),
		"extra_keys", len(res.ExtraKeys),
	)
	return res, nil
}

// EqualJSON reports whether expected and actual JSON objects contain identical
// key/value pairs.
func EqualJSON(expected, actual []byte) (bool, error) {
	res, err := CompareJSON(expected, actual)
	if err != nil {
		return false, err
	}
	return res.Equal, nil
}

func normalizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
