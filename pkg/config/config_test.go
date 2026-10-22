// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const sampleConfig = `
version: 1
rules:
  - name: registry
    path: ./data
    policy: policies/signed.hjson
    owner:
      scheme: host
  - path: vendor/
    depth: 1
    policy: git+https://github.com/carabiner-dev/policies@abc123#gitsign/gitsign-commit-signature.hjson
    owner:
      scheme: file
      file: config.json
      pointer: /owner/url
    ownerContext: [signers]
  - path: docs
    policy: policies/docs.json
`

func TestParseDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(sampleConfig))
	require.NoError(t, err)
	require.Equal(t, Deny, cfg.Unmatched)
	require.Len(t, cfg.Rules, 3)

	reg := cfg.Rules[0]
	require.Equal(t, "data/", reg.Path)
	require.Equal(t, 1, reg.GetDepth())
	require.Equal(t, DefaultWellKnown, reg.Owner.WellKnown)
	require.Equal(t, Deny, reg.OnMissingOwner)
	require.Equal(t, "registry", reg.Label())

	vendor := cfg.Rules[1]
	require.Equal(t, SchemeFile, vendor.Owner.Scheme)
	require.Equal(t, "json", vendor.Owner.Format)
	require.Equal(t, "vendor/", vendor.Label())

	docs := cfg.Rules[2]
	require.Equal(t, SchemeNone, docs.Owner.Scheme)
	require.Equal(t, 0, docs.GetDepth())
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		cfg  string
		want string
	}{
		"version":       {"version: 2\nrules: [{path: a, policy: p}]", "unsupported configuration version"},
		"norules":       {"version: 1\nrules: []", "no rules"},
		"nopolicy":      {"version: 1\nrules: [{path: a}]", "no policy"},
		"hostdepth":     {"version: 1\nrules: [{path: a, policy: p, depth: 2, owner: {scheme: host}}]", "requires depth 1"},
		"filenopointer": {"version: 1\nrules: [{path: a, policy: p, owner: {scheme: file, file: c.json}}]", "requires a pointer"},
		"fileescape":    {"version: 1\nrules: [{path: a, policy: p, owner: {scheme: file, file: ../c.txt}}]", "relative to the owned path"},
		"badscheme":     {"version: 1\nrules: [{path: a, policy: p, owner: {scheme: dns}}]", "unknown owner scheme"},
		"dotdot":        {"version: 1\nrules: [{path: ../a, policy: p}]", "must not contain"},
		"badDecision":   {"version: 1\nunmatched: maybe\nrules: [{path: a, policy: p}]", "invalid decision"},
		"unknownField":  {"version: 1\nrules: [{path: a, policy: p, bogus: 1}]", "field bogus not found"},
		"badctx":        {"version: 1\nrules: [{path: a, policy: p, ownerContext: ['a-b']}]", "invalid context value name"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.cfg))
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte(sampleConfig))
	require.NoError(t, err)

	units, shallow, unmatched := cfg.Match([]string{
		"data/example.com/a.txt",
		"data/example.com/sub/b.txt",
		"data/other.org/c.txt",
		"data/README.md",
		"vendor/acme/config.json",
		"docs/index.md",
		"docs/guide/intro.md",
		"README.md",
		"./data/example.com/d.txt",
	})
	require.Equal(t, []string{"README.md"}, unmatched)
	require.Len(t, shallow, 1)
	require.Contains(t, shallow, "data/README.md")

	require.Len(t, units, 4)
	byPath := map[string]*Unit{}
	for _, u := range units {
		byPath[u.Path] = u
	}
	require.ElementsMatch(t, []string{"data/example.com/a.txt", "data/example.com/sub/b.txt", "data/example.com/d.txt"}, byPath["data/example.com/"].Files)
	require.Equal(t, []string{"example.com"}, byPath["data/example.com/"].Segments)
	require.Equal(t, []string{"data/other.org/c.txt"}, byPath["data/other.org/"].Files)
	require.Equal(t, []string{"vendor/acme/config.json"}, byPath["vendor/acme/"].Files)
	require.Equal(t, []string{"docs/index.md", "docs/guide/intro.md"}, byPath["docs/"].Files)
	require.Empty(t, byPath["docs/"].Segments)
}

func TestMatchRootRule(t *testing.T) {
	t.Parallel()
	cfg, err := Parse([]byte("version: 1\nrules: [{path: /, policy: p}]"))
	require.NoError(t, err)
	units, shallow, unmatched := cfg.Match([]string{"a", "b/c"})
	require.Empty(t, unmatched)
	require.Empty(t, shallow)
	require.Len(t, units, 1)
	require.Empty(t, units[0].Path)
	require.Equal(t, []string{"a", "b/c"}, units[0].Files)
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	require.Empty(t, NormalizeDir("/"))
	require.Empty(t, NormalizeDir("."))
	require.Equal(t, "a/b/", NormalizeDir("./a//b/"))
	require.Equal(t, "a/b", NormalizeFile("./a/./b"))
}
