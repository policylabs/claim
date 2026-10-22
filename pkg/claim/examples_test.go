// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package claim

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/claim/pkg/config"
	"github.com/policylabs/claim/pkg/material"
	"github.com/policylabs/claim/pkg/owner"
)

// TestExamples keeps the shipped examples parseable.
func TestExamples(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "examples")

	cfgData, err := os.ReadFile(filepath.Join(root, "registry", ".claim.yaml"))
	require.NoError(t, err)
	cfg, err := config.Parse(cfgData)
	require.NoError(t, err)
	require.Len(t, cfg.Rules, 3)

	read := func(p string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, "registry", filepath.FromSlash(p)))
	}
	mat, err := material.Load("policies/signed-by-owner.json", read, true)
	require.NoError(t, err)
	require.Equal(t, []string{"signers"}, mat.RequiredOpen())
	require.Equal(t, []string{"signers"}, mat.OwnerFillable(cfg.Rules[0].OwnerContext))
	// The issuer has a default, so the owner cannot touch it unless listed.
	require.Equal(t, []string{"signers"}, mat.OwnerFillable(nil))
	require.Equal(t, []string{"issuer", "signers"}, mat.OwnerFillable([]string{"signers", "issuer"}))

	docData, err := os.ReadFile(filepath.Join(root, "owner", "claim.yaml"))
	require.NoError(t, err)
	doc, err := owner.ParseDocument(docData)
	require.NoError(t, err)
	ctx := doc.ContextFor("github.com/some-org/registry", "data/example.com/")
	require.Equal(t, []any{"alice@example.com", "registry-bot@example.com"}, ctx["signers"])

	// The vendor pointer file resolves to a git locator with the default
	// document path.
	o, err := owner.Resolve(&config.Unit{Rule: cfg.Rules[1], Path: "vendor/acme/", Segments: []string{"acme"}}, owner.FileReader(read))
	require.NoError(t, err)
	require.Equal(t, "git+https://github.com/acme/owners@main#claim.yaml", o.String())
}
