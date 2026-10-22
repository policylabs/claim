// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package owner

import (
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	acontext "github.com/policylabs/ampel/pkg/context"
	"gopkg.in/yaml.v3"
)

// DocumentVersion is the owner document schema version understood today.
const DocumentVersion = 1

// Document is the file an owner publishes to supply the context values the
// repository policy leaves open. Values are resolved most specific first:
// repositories[repo].paths[path] > repositories[repo] > paths[path] > context.
//
//	version: 1
//	context:
//	  signers: ["alice@example.com"]
//	paths:
//	  "data/example.com/":
//	    context: { signers: ["bob@example.com"] }
//	repositories:
//	  "github.com/org/registry":
//	    context: {...}
//	    paths: {...}
type Document struct {
	Version      int                   `json:"version"                yaml:"version"`
	Context      map[string]any        `json:"context,omitempty"      yaml:"context,omitempty"`
	Paths        map[string]*Scope     `json:"paths,omitempty"        yaml:"paths,omitempty"`
	Repositories map[string]*RepoScope `json:"repositories,omitempty" yaml:"repositories,omitempty"`
}

// Scope holds context values for one owned path.
type Scope struct {
	Context map[string]any `json:"context,omitempty" yaml:"context,omitempty"`
}

// RepoScope holds context values for one repository, optionally per path.
type RepoScope struct {
	Context map[string]any    `json:"context,omitempty" yaml:"context,omitempty"`
	Paths   map[string]*Scope `json:"paths,omitempty"   yaml:"paths,omitempty"`
}

// ParseDocument decodes an owner document (YAML or JSON).
func ParseDocument(data []byte) (*Document, error) {
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("owner document is empty")
	}
	doc := &Document{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil {
		return nil, fmt.Errorf("decoding owner document: %w", err)
	}
	if doc.Version != DocumentVersion {
		return nil, fmt.Errorf("unsupported owner document version %d (want %d)", doc.Version, DocumentVersion)
	}
	return doc, nil
}

// ContextFor flattens the document into the context values that apply to a
// path of a repository. repo is a host/org/name slug such as
// "github.com/org/repo" (may be empty); path is the owned path with a
// trailing slash.
func (doc *Document) ContextFor(repo, path string) map[string]any {
	out := map[string]any{}
	maps.Copy(out, doc.Context)
	if s := lookupScope(doc.Paths, path); s != nil {
		maps.Copy(out, s.Context)
	}
	if repo != "" {
		if rs := lookupRepo(doc.Repositories, repo); rs != nil {
			maps.Copy(out, rs.Context)
			if s := lookupScope(rs.Paths, path); s != nil {
				maps.Copy(out, s.Context)
			}
		}
	}
	return out
}

func lookupScope(m map[string]*Scope, path string) *Scope {
	if m == nil {
		return nil
	}
	want := normalizePath(path)
	for k, v := range m {
		if normalizePath(k) == want {
			return v
		}
	}
	return nil
}

func lookupRepo(m map[string]*RepoScope, repo string) *RepoScope {
	if m == nil {
		return nil
	}
	want := strings.ToLower(strings.Trim(repo, "/"))
	for k, v := range m {
		if strings.ToLower(strings.Trim(k, "/")) == want {
			return v
		}
	}
	return nil
}

func normalizePath(p string) string {
	p = strings.TrimPrefix(strings.TrimSpace(p), "./")
	return strings.Trim(p, "/")
}

// Provider wraps a set of context values as an AMPEL context provider that
// only answers for the allowed keys. The owner document is untrusted input
// from the repository's point of view, so the policy (through claim) decides
// which values the owner is permitted to supply.
type Provider struct {
	values  map[string]any
	allowed map[string]struct{}
}

var _ acontext.Provider = (*Provider)(nil)

// ErrKeyClash is returned when the owner document defines context names that
// collide once lowercased, or that differ only in case from an allowed name.
// AMPEL forbids such names, and an owner must not be able to smuggle a value
// in under a differently cased spelling.
var ErrKeyClash = errors.New("owner document context names clash when lowercased")

// NewProvider builds a provider exposing only the allowed keys of values.
// Keys the policy does not allow are dropped; keys that clash with an allowed
// key or with each other once lowercased are an error.
func NewProvider(values map[string]any, allowed []string) (*Provider, error) {
	p := &Provider{values: map[string]any{}, allowed: map[string]struct{}{}}
	lcAllowed := map[string]string{}
	for _, k := range allowed {
		p.allowed[k] = struct{}{}
		lcAllowed[strings.ToLower(k)] = k
	}
	seen := map[string]string{}
	for k, v := range values {
		lc := strings.ToLower(k)
		if prev, ok := seen[lc]; ok {
			return nil, fmt.Errorf("%w: %q and %q", ErrKeyClash, prev, k)
		}
		seen[lc] = k
		if want, ok := lcAllowed[lc]; ok && want != k {
			return nil, fmt.Errorf("%w: %q differs only in case from %q", ErrKeyClash, k, want)
		}
		if _, ok := p.allowed[k]; ok {
			p.values[k] = v
		}
	}
	return p, nil
}

// GetContextValue implements acontext.Provider.
func (p *Provider) GetContextValue(key string) (any, error) {
	if v, ok := p.values[key]; ok {
		return v, nil
	}
	return nil, nil
}

// GetContextMap implements acontext.Provider.
func (p *Provider) GetContextMap(keys []string) (map[string]any, error) {
	ret := map[string]any{}
	for _, k := range keys {
		if v, ok := p.values[k]; ok {
			ret[k] = v
		}
	}
	return ret, nil
}

// Keys returns the keys the provider will answer for, sorted.
func (p *Provider) Keys() []string {
	keys := make([]string, 0, len(p.values))
	for k := range p.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
