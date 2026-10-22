// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package material loads the AMPEL policy material a rule points to and
// inspects the context values it leaves open for the path owner to fill.
package material

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/policylabs/policy"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

// Material is a compiled policy, policy set or policy group.
type Material struct {
	// Location the material was loaded from.
	Location string
	// Local is true when the material came from the repository itself.
	Local bool
	// Set, Policy and Group hold the compiled material; exactly one is set.
	Set    *papi.PolicySet
	Policy *papi.Policy
	Group  *papi.PolicyGroup
	// Verification of the material signature, when it was signed.
	Verification attestation.Verification
}

// Object returns the compiled material in the form the AMPEL verifier takes.
func (m *Material) Object() any {
	return policy.PolicyOrSetOrGroup(m.Set, m.Policy, m.Group)
}

// ID returns the identifier of the material.
func (m *Material) ID() string {
	switch {
	case m.Set != nil:
		return m.Set.GetId()
	case m.Policy != nil:
		return m.Policy.GetId()
	case m.Group != nil:
		return m.Group.GetId()
	}
	return ""
}

// FileReader reads a repository-relative file from the trusted merge target.
type FileReader func(path string) ([]byte, error)

// IsRemote reports whether a policy location points outside the repository.
func IsRemote(location string) bool {
	l := strings.ToLower(location)
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") ||
		strings.HasPrefix(l, "git+https://") || strings.HasPrefix(l, "git+ssh://")
}

// Load compiles the material at location. Repository-relative locations are
// read through read (the merge target), remote locations are fetched by the
// policy compiler. Signed material is verified when verify is true.
func Load(location string, read FileReader, verify bool) (*Material, error) {
	if location == "" {
		return nil, errors.New("empty policy location")
	}
	compiler := policy.NewCompiler()
	opts := []options.OptFn{options.WithVerifySignatures(verify)}
	m := &Material{Location: location}
	var err error
	if IsRemote(location) {
		if strings.HasPrefix(strings.ToLower(location), "http://") {
			return nil, fmt.Errorf("refusing to load policy over plain http: %s", location)
		}
		m.Set, m.Policy, m.Group, m.Verification, err = compiler.CompileVerifyLocation(location, opts...)
		if err != nil {
			return nil, fmt.Errorf("compiling remote policy %s: %w", location, err)
		}
	} else {
		if read == nil {
			return nil, errors.New("no file reader to load the repository policy")
		}
		if strings.Contains(location, "..") {
			return nil, fmt.Errorf("policy location %q must not contain '..'", location)
		}
		data, err := read(location)
		if err != nil {
			return nil, fmt.Errorf("reading policy %s from merge target: %w", location, err)
		}
		m.Local = true
		m.Set, m.Policy, m.Group, m.Verification, err = compiler.CompileVerify(data, opts...)
		if err != nil {
			return nil, fmt.Errorf("compiling policy %s: %w", location, err)
		}
	}
	if verify && m.Verification != nil && !m.Verification.GetVerified() {
		return nil, fmt.Errorf("policy %s: signature verification failed", location)
	}
	if m.Set == nil && m.Policy == nil && m.Group == nil {
		return nil, fmt.Errorf("policy %s compiled to nothing", location)
	}
	return m, nil
}

// ContextKey describes one context value definition found in the material.
type ContextKey struct {
	Name string
	// Open is true when the policy neither burns in a value nor computes it
	// with an expression nor supplies a default: an external provider must
	// fill it.
	Open bool
	// HasDefault is true when the policy supplies a default that providers
	// may override.
	HasDefault bool
	// Required is true when the policy marks the value as required.
	Required bool
	// Burned is true when the value is fixed in policy code (value or
	// expression) and no provider can change it.
	Burned bool
}

// ContextKeys walks the material and returns every context value it
// defines, merging policy level definitions over set and group commons the
// same way AMPEL does.
func (m *Material) ContextKeys() []ContextKey {
	defs := map[string]*papi.ContextVal{}
	merge := func(ctx map[string]*papi.ContextVal) {
		for k, v := range ctx {
			if existing, ok := defs[k]; ok {
				clone := &papi.ContextVal{}
				clone.Merge(existing)
				clone.Merge(v)
				defs[k] = clone
				continue
			}
			clone := &papi.ContextVal{}
			clone.Merge(v)
			defs[k] = clone
		}
	}
	switch {
	case m.Policy != nil:
		merge(m.Policy.GetContext())
	case m.Set != nil:
		merge(m.Set.GetCommon().GetContext())
		for _, p := range m.Set.GetPolicies() {
			merge(p.GetContext())
		}
		for _, g := range m.Set.GetGroups() {
			merge(g.GetCommon().GetContext())
			for _, b := range g.GetBlocks() {
				for _, p := range b.GetPolicies() {
					merge(p.GetContext())
				}
			}
		}
	case m.Group != nil:
		merge(m.Group.GetCommon().GetContext())
		for _, b := range m.Group.GetBlocks() {
			for _, p := range b.GetPolicies() {
				merge(p.GetContext())
			}
		}
	}
	keys := make([]ContextKey, 0, len(defs))
	for name, def := range defs {
		burned := def.Value != nil || def.GetExpression() != ""
		keys = append(keys, ContextKey{
			Name:       name,
			Burned:     burned,
			HasDefault: def.Default != nil,
			Required:   def.GetRequired(),
			Open:       !burned && def.Default == nil,
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys
}

// OwnerFillable returns the names of the context values the owner document
// may supply. With an explicit allow list only its members are fillable and
// then only when the policy does not burn them in. Without one, every open
// key is fillable.
func (m *Material) OwnerFillable(allow []string) []string {
	keys := m.ContextKeys()
	out := []string{}
	if len(allow) > 0 {
		byName := map[string]ContextKey{}
		for _, k := range keys {
			byName[k.Name] = k
		}
		for _, name := range allow {
			k, ok := byName[name]
			if !ok || k.Burned {
				continue
			}
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	for _, k := range keys {
		if k.Open {
			out = append(out, k.Name)
		}
	}
	return out
}

// RequiredOpen returns the open context values the policy requires. Every one
// of them must be supplied (locally or by the owner) for AMPEL to evaluate.
func (m *Material) RequiredOpen() []string {
	out := []string{}
	for _, k := range m.ContextKeys() {
		if k.Open && k.Required {
			out = append(out, k.Name)
		}
	}
	return out
}
