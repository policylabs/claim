// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package material

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const testPolicy = `{
  "id": "ctx-test",
  "context": {
    "signers": {"required": true},
    "optional": {},
    "withDefault": {"default": "x"},
    "fixed": {"value": "y"},
    "computed": {"expression": "subject.name"}
  },
  "predicates": {"types": ["https://example.com/t/v1"]},
  "tenets": [{"id": "t", "code": "true"}]
}`

func TestContextKeys(t *testing.T) {
	t.Parallel()
	read := func(p string) ([]byte, error) {
		if p == "policies/p.json" {
			return []byte(testPolicy), nil
		}
		return nil, errors.New("not found")
	}
	m, err := Load("policies/p.json", read, true)
	require.NoError(t, err)
	require.True(t, m.Local)
	require.NotNil(t, m.Policy)
	require.Equal(t, "ctx-test", m.ID())

	keys := m.ContextKeys()
	byName := map[string]ContextKey{}
	for _, k := range keys {
		byName[k.Name] = k
	}
	require.Len(t, byName, 5)
	require.True(t, byName["signers"].Open)
	require.True(t, byName["signers"].Required)
	require.True(t, byName["optional"].Open)
	require.False(t, byName["optional"].Required)
	require.False(t, byName["withDefault"].Open)
	require.True(t, byName["withDefault"].HasDefault)
	require.True(t, byName["fixed"].Burned)
	require.True(t, byName["computed"].Burned)

	require.Equal(t, []string{"optional", "signers"}, m.OwnerFillable(nil))
	require.Equal(t, []string{"signers", "withDefault"}, m.OwnerFillable([]string{"signers", "withDefault", "fixed", "computed", "unknown"}))
	require.Equal(t, []string{"signers"}, m.RequiredOpen())

	_, err = Load("policies/missing.json", read, true)
	require.ErrorContains(t, err, "reading policy")
	_, err = Load("../escape.json", read, true)
	require.ErrorContains(t, err, "must not contain")
	_, err = Load("http://example.com/p.json", read, true)
	require.ErrorContains(t, err, "plain http")
	_, err = Load("", read, true)
	require.Error(t, err)
}

func TestContextKeysSet(t *testing.T) {
	t.Parallel()
	set := `{
	  "id": "set",
	  "common": {"context": {"signers": {"required": true}, "team": {"default": "a"}}},
	  "policies": [
	    {"id": "p1", "context": {"team": {"required": true}}, "predicates": {"types": ["https://example.com/t/v1"]}, "tenets": [{"id": "t", "code": "true"}]},
	    {"id": "p2", "context": {"extra": {}}, "predicates": {"types": ["https://example.com/t/v1"]}, "tenets": [{"id": "t", "code": "true"}]}
	  ]
	}`
	m, err := Load("set.json", func(string) ([]byte, error) { return []byte(set), nil }, true)
	require.NoError(t, err)
	require.NotNil(t, m.Set)
	// team keeps its common default even though p1 marks it required.
	require.Equal(t, []string{"extra", "signers"}, m.OwnerFillable(nil))
	require.Equal(t, []string{"signers"}, m.RequiredOpen())
}
