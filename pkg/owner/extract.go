// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package owner

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExtractURL pulls the owner URL string out of a file. format is json, yaml
// or text; pointer is an RFC 6901 JSON pointer into json/yaml documents and
// is ignored for text, where the trimmed file contents are the URL.
func ExtractURL(data []byte, format, pointer string) (string, error) {
	switch format {
	case "text":
		s := strings.TrimSpace(string(data))
		if s == "" {
			return "", errors.New("owner file is empty")
		}
		// Only the first line counts, so a comment or trailing junk never
		// becomes part of the URL.
		if i := strings.IndexAny(s, "\r\n"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		return s, nil
	case "json":
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return "", fmt.Errorf("parsing owner json file: %w", err)
		}
		return pointerString(doc, pointer)
	case "yaml":
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return "", fmt.Errorf("parsing owner yaml file: %w", err)
		}
		return pointerString(doc, pointer)
	default:
		return "", fmt.Errorf("unknown owner file format %q", format)
	}
}

func pointerString(doc any, pointer string) (string, error) {
	v, err := JSONPointer(doc, pointer)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("value at %q is %T, want a string", pointer, v)
	}
	return s, nil
}

// JSONPointer resolves an RFC 6901 pointer against a decoded JSON/YAML
// document (maps and slices).
func JSONPointer(doc any, pointer string) (any, error) {
	if pointer == "" {
		return doc, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("pointer %q must start with /", pointer)
	}
	cur := doc
	for _, raw := range strings.Split(pointer[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return nil, fmt.Errorf("pointer %q: key %q not found", pointer, token)
			}
			cur = next
		case map[any]any: // yaml.v3 may produce this for non-string keys
			next, ok := node[token]
			if !ok {
				return nil, fmt.Errorf("pointer %q: key %q not found", pointer, token)
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(token)
			if err != nil || i < 0 || i >= len(node) {
				return nil, fmt.Errorf("pointer %q: bad index %q", pointer, token)
			}
			cur = node[i]
		default:
			return nil, fmt.Errorf("pointer %q: cannot descend into %T at %q", pointer, cur, token)
		}
	}
	return cur, nil
}
