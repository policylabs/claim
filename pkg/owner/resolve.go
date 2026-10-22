// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package owner discovers who owns a path and fetches the document they
// publish to complete the repository policy.
package owner

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/policylabs/claim/pkg/config"
)

// ErrNoOwner is returned when the owner of a path cannot be determined. The
// rule's onMissingOwner decision applies.
var ErrNoOwner = errors.New("owner not found")

// Owner is the resolved location of an owner document.
type Owner struct {
	// Kind of location.
	Kind Kind
	// URL of the document. For KindGit the path holds org/repo[@ref] and the
	// fragment the file inside the repository.
	URL *url.URL
	// Source describes where the owner came from, for reporting.
	Source string
}

// String renders the owner location.
func (o *Owner) String() string {
	if o == nil || o.URL == nil {
		return ""
	}
	if o.Kind == KindGit {
		return GitLocator(o.URL)
	}
	return o.URL.String()
}

// FileReader reads a repository file from the trusted merge target.
type FileReader func(path string) ([]byte, error)

// Resolve determines the owner of a unit according to its rule. read gives
// access to files in the base commit (never the PR head).
func Resolve(unit *config.Unit, read FileReader) (*Owner, error) {
	rule := unit.Rule
	switch rule.Owner.Scheme {
	case config.SchemeNone:
		return nil, nil
	case config.SchemeHost:
		return resolveHost(unit)
	case config.SchemeFile:
		return resolveFile(unit, read)
	default:
		return nil, fmt.Errorf("unknown owner scheme %q", rule.Owner.Scheme)
	}
}

func resolveHost(unit *config.Unit) (*Owner, error) {
	if len(unit.Segments) != 1 {
		return nil, fmt.Errorf("%w: host scheme needs exactly one path segment, got %v", ErrNoOwner, unit.Segments)
	}
	host := unit.Segments[0]
	if err := ValidateHostname(host); err != nil {
		return nil, fmt.Errorf("%w: path segment %q is not a usable host: %w", ErrNoOwner, host, err)
	}
	wk := unit.Rule.Owner.WellKnown
	if wk == "" {
		wk = config.DefaultWellKnown
	}
	u, kind, err := ParseOwnerURL(schemeHTTPS + "://" + strings.ToLower(host) + wk)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoOwner, err)
	}
	return &Owner{Kind: kind, URL: u, Source: "derived from path segment " + host}, nil
}

func resolveFile(unit *config.Unit, read FileReader) (*Owner, error) {
	if read == nil {
		return nil, errors.New("no file reader to resolve owner from")
	}
	o := unit.Rule.Owner
	file := path.Join(unit.Path, o.File)
	data, err := read(file)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s from merge target: %w", ErrNoOwner, file, err)
	}
	raw, err := ExtractURL(data, o.Format, o.Pointer)
	if err != nil {
		return nil, fmt.Errorf("%w: extracting owner URL from %s: %w", ErrNoOwner, file, err)
	}
	u, kind, err := ParseOwnerURL(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNoOwner, file, err)
	}
	applyDefaultDocument(u, kind, o.Document)
	return &Owner{Kind: kind, URL: u, Source: "extracted from " + file}, nil
}

// applyDefaultDocument fills in the document path when the owner URL only
// names a host or a repository.
func applyDefaultDocument(u *url.URL, kind Kind, document string) {
	switch kind {
	case KindHTTPS:
		if u.Path == "" || u.Path == "/" {
			if document == "" {
				document = config.DefaultWellKnown
			}
			u.Path = "/" + strings.TrimPrefix(document, "/")
		}
	case KindGit:
		if u.Fragment == "" {
			if document == "" {
				document = config.DefaultGitDocument
			}
			u.Fragment = strings.TrimPrefix(document, "/")
		}
	}
}
