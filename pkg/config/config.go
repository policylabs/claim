// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package config parses and validates the repository's claim configuration.
//
// The configuration file (.claim.yaml by default) lives in the repository
// that receives pull requests. It maps path prefixes to the AMPEL policy that
// gates changes under them and to the scheme used to find the URL that "owns"
// each path. The configuration MUST always be read from the merge target (the
// base branch), never from the pull request head: a PR could otherwise rewrite
// the rules it is being evaluated against.
package config

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultFileName is the name of the configuration file at the repository root.
const DefaultFileName = ".claim.yaml"

// CurrentVersion is the only configuration schema version understood today.
const CurrentVersion = 1

// Decision is a fail-open / fail-closed switch used across the configuration.
type Decision string

const (
	// Deny blocks the change. This is always the default.
	Deny Decision = "deny"
	// Allow lets the change through. It must be opted into explicitly.
	Allow Decision = "allow"
)

// OwnerScheme selects how the owner URL of a path is discovered.
type OwnerScheme string

const (
	// SchemeNone means the path has no remote owner. The policy must be
	// satisfiable with the data available in the repository alone.
	SchemeNone OwnerScheme = "none"

	// SchemeHost derives the owner from the path itself: the owned segment
	// (eg "example.com" in data/example.com/...) is a host name and the owner
	// document is served from https://<host><wellKnown>.
	SchemeHost OwnerScheme = "host"

	// SchemeFile extracts the owner URL from a file inside the owned path, as
	// it exists in the merge target.
	SchemeFile OwnerScheme = "file"
)

// Config is the top level claim configuration.
type Config struct {
	// Version of the configuration schema. Must be 1.
	Version int `json:"version" yaml:"version"`

	// Unmatched decides what happens to changed files no rule matches.
	// Defaults to deny.
	Unmatched Decision `json:"unmatched,omitempty" yaml:"unmatched,omitempty"`

	// Rules is the ordered list of path rules. The first rule whose Path
	// matches a changed file wins.
	Rules []*Rule `json:"rules" yaml:"rules"`
}

// Rule gates the changes made to a path prefix.
type Rule struct {
	// Name is an optional label for reporting.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Path is the repository-relative directory the rule covers (eg "data/").
	// A rule with Path "" or "/" covers the whole repository.
	Path string `json:"path" yaml:"path"`

	// Depth is the number of path segments under Path that form one owned
	// unit. With Path "data/" and Depth 1, "data/example.com/a/b.txt" belongs
	// to the owned path "data/example.com/". Depth 0 makes the rule path
	// itself the unit. Defaults to 0 for the none scheme and 1 otherwise.
	// With the host scheme it must be 1.
	Depth *int `json:"depth,omitempty" yaml:"depth,omitempty"`

	// Policy is the location of the AMPEL policy, policy set or group. It can
	// be a repository-relative file (read from the merge target), an https
	// URL or a git+https VCS locator. Remote policies should be pinned to a
	// commit.
	Policy string `json:"policy" yaml:"policy"`

	// Owner configures how the owner URL for the matched path is discovered.
	Owner Owner `json:"owner" yaml:"owner"`

	// OnMissingOwner decides what happens when an owner cannot be determined
	// (no file to extract from, invalid host, unreachable document, ...).
	// Defaults to deny.
	OnMissingOwner Decision `json:"onMissingOwner,omitempty" yaml:"onMissingOwner,omitempty"`

	// OwnerContext is the list of context value names the owner document is
	// allowed to supply. When empty, the owner may fill every context value
	// the policy leaves open (no value, no default, no expression). Listing
	// names here is the only way to let an owner override a policy default.
	OwnerContext []string `json:"ownerContext,omitempty" yaml:"ownerContext,omitempty"`

	// Collectors are extra AMPEL collector init strings to add for this rule
	// in addition to the defaults (gitsign and git notes on the PR repo).
	Collectors []string `json:"collectors,omitempty" yaml:"collectors,omitempty"`
}

// Owner describes how the URL owning a path is found.
type Owner struct {
	// Scheme is one of none, host or file.
	Scheme OwnerScheme `json:"scheme" yaml:"scheme"`

	// WellKnown is the path of the owner document on the derived host when
	// Scheme is host. Defaults to /.well-known/claim.yaml.
	WellKnown string `json:"wellKnown,omitempty" yaml:"wellKnown,omitempty"`

	// File is the file, relative to the owned path, holding the owner URL
	// when Scheme is file (eg "config.json").
	File string `json:"file,omitempty" yaml:"file,omitempty"`

	// Format of File: json, yaml or text. Inferred from the extension when
	// empty. Text files hold the bare URL.
	Format string `json:"format,omitempty" yaml:"format,omitempty"`

	// Pointer is an RFC 6901 JSON pointer to the owner URL inside a json or
	// yaml File (eg "/owner/url"). Required for json and yaml formats.
	Pointer string `json:"pointer,omitempty" yaml:"pointer,omitempty"`

	// Digests optionally pins the owner document to one of these sha256:<hex>
	// digests. A document that matches none is treated as missing. Pinning
	// trades the distributed update model for an explicit rotation step in
	// this repository; use it where the owner cannot yet sign its document.
	Digests []string `json:"digests,omitempty" yaml:"digests,omitempty"`

	// Document is the path of the owner document relative to the owner URL
	// when the extracted URL points to an https host without a path, or to
	// a git repository without a subpath. Defaults to /.well-known/claim.yaml
	// for https and claim.yaml for git locators.
	Document string `json:"document,omitempty" yaml:"document,omitempty"`
}

// DefaultWellKnown is the default owner document location on an https host.
const DefaultWellKnown = "/.well-known/claim.yaml"

// DefaultGitDocument is the default owner document path inside a git repo.
const DefaultGitDocument = "claim.yaml"

// Parse reads a configuration document (YAML or JSON) and validates it.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.Unmatched == "" {
		cfg.Unmatched = Deny
	}
	for _, r := range cfg.Rules {
		if r == nil {
			continue
		}
		r.Path = NormalizeDir(r.Path)
		if r.OnMissingOwner == "" {
			r.OnMissingOwner = Deny
		}
		if r.Owner.Scheme == "" {
			r.Owner.Scheme = SchemeNone
		}
		if r.Depth == nil {
			d := 1
			if r.Owner.Scheme == SchemeNone {
				d = 0
			}
			r.Depth = &d
		}
		if r.Owner.Scheme == SchemeHost && r.Owner.WellKnown == "" {
			r.Owner.WellKnown = DefaultWellKnown
		}
		if r.Owner.Scheme == SchemeFile && r.Owner.Format == "" {
			r.Owner.Format = formatFromExtension(r.Owner.File)
		}
	}
}

func formatFromExtension(file string) string {
	switch strings.ToLower(path.Ext(file)) {
	case ".json", ".hjson":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".txt", ".url", "":
		return "text"
	default:
		return ""
	}
}

// Validate checks the configuration for errors.
func (cfg *Config) Validate() error {
	errs := []error{}
	if cfg.Version != CurrentVersion {
		errs = append(errs, fmt.Errorf("unsupported configuration version %d (want %d)", cfg.Version, CurrentVersion))
	}
	if err := validateDecision("unmatched", cfg.Unmatched); err != nil {
		errs = append(errs, err)
	}
	if len(cfg.Rules) == 0 {
		errs = append(errs, errors.New("configuration defines no rules"))
	}
	for i, r := range cfg.Rules {
		if r == nil {
			errs = append(errs, fmt.Errorf("rule %d is empty", i))
			continue
		}
		if err := r.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", i, r.Label(), err))
		}
	}
	return errors.Join(errs...)
}

func validateDecision(field string, d Decision) error {
	switch d {
	case Allow, Deny:
		return nil
	default:
		return fmt.Errorf("%s: invalid decision %q (allow or deny)", field, d)
	}
}

// GetDepth returns the rule depth (0 when unset).
func (r *Rule) GetDepth() int {
	if r.Depth == nil {
		return 0
	}
	return *r.Depth
}

// Label returns the rule name or its path for reporting.
func (r *Rule) Label() string {
	if r.Name != "" {
		return r.Name
	}
	if r.Path == "" {
		return "/"
	}
	return r.Path
}

// Validate checks a rule.
func (r *Rule) Validate() error {
	errs := []error{}
	if strings.Contains(r.Path, "..") {
		errs = append(errs, fmt.Errorf("path %q must not contain '..'", r.Path))
	}
	if strings.HasPrefix(r.Path, "/") {
		errs = append(errs, fmt.Errorf("path %q must be repository-relative", r.Path))
	}
	if r.GetDepth() < 0 {
		errs = append(errs, fmt.Errorf("depth must not be negative"))
	}
	if r.Policy == "" {
		errs = append(errs, errors.New("rule defines no policy"))
	}
	if err := validateDecision("onMissingOwner", r.OnMissingOwner); err != nil {
		errs = append(errs, err)
	}
	for _, c := range r.OwnerContext {
		if !isValidContextName(c) {
			errs = append(errs, fmt.Errorf("invalid context value name %q in ownerContext", c))
		}
	}
	switch r.Owner.Scheme {
	case SchemeNone:
		if len(r.Owner.Digests) > 0 {
			errs = append(errs, errors.New("owner scheme none takes no digests"))
		}
		if r.Owner.File != "" || r.Owner.Pointer != "" || r.Owner.WellKnown != "" {
			errs = append(errs, errors.New("owner scheme none takes no other owner settings"))
		}
	case SchemeHost:
		if r.GetDepth() != 1 {
			errs = append(errs, errors.New("owner scheme host requires depth 1"))
		}
		if !strings.HasPrefix(r.Owner.WellKnown, "/") {
			errs = append(errs, fmt.Errorf("wellKnown %q must be an absolute path", r.Owner.WellKnown))
		}
		if r.Owner.File != "" || r.Owner.Pointer != "" {
			errs = append(errs, errors.New("owner scheme host does not take file or pointer"))
		}
	case SchemeFile:
		if r.Owner.File == "" {
			errs = append(errs, errors.New("owner scheme file requires a file"))
		}
		if strings.Contains(r.Owner.File, "..") || strings.HasPrefix(r.Owner.File, "/") {
			errs = append(errs, fmt.Errorf("owner file %q must be relative to the owned path", r.Owner.File))
		}
		switch r.Owner.Format {
		case "json", "yaml":
			if r.Owner.Pointer == "" {
				errs = append(errs, fmt.Errorf("owner format %s requires a pointer", r.Owner.Format))
			} else if !strings.HasPrefix(r.Owner.Pointer, "/") {
				errs = append(errs, fmt.Errorf("pointer %q must start with /", r.Owner.Pointer))
			}
		case "text":
			if r.Owner.Pointer != "" {
				errs = append(errs, errors.New("owner format text does not take a pointer"))
			}
		default:
			errs = append(errs, fmt.Errorf("unknown owner file format %q (json, yaml or text)", r.Owner.Format))
		}
	default:
		errs = append(errs, fmt.Errorf("unknown owner scheme %q (none, host or file)", r.Owner.Scheme))
	}
	for _, d := range r.Owner.Digests {
		algo, val, ok := strings.Cut(d, ":")
		if !ok || !strings.EqualFold(algo, "sha256") || len(val) != 64 {
			errs = append(errs, fmt.Errorf("invalid pinned digest %q (want sha256:<64 hex>)", d))
		}
	}
	return errors.Join(errs...)
}

// isValidContextName mirrors AMPEL's context naming rules: letters, digits
// and underscores.
func isValidContextName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// NormalizeDir cleans a repository-relative directory: forward slashes, no
// leading "./" or "/", and a single trailing slash (or "" for the root).
func NormalizeDir(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.Trim(p, "/")
	if p == "" || p == "." {
		return ""
	}
	return path.Clean(p) + "/"
}

// NormalizeFile cleans a repository-relative file path.
func NormalizeFile(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return path.Clean(p)
}

// Unit is an owned path: the rule that matched and the directory that forms
// the ownership unit, with the changed files that fall under it.
type Unit struct {
	Rule *Rule
	// Path is the owned directory, eg "data/example.com/".
	Path string
	// Segments are the Depth path elements under the rule path, eg
	// ["example.com"]. Empty for depth 0 rules.
	Segments []string
	// Files are the changed files under the owned path.
	Files []string
}

// Key identifies the unit.
func (u *Unit) Key() string {
	return u.Rule.Label() + "::" + u.Path
}

// Match groups the changed files by owned unit. Files matched by a rule but
// shallower than the rule's depth (eg "data/README.md" for a depth 1 rule on
// data/) have no owner segment: they are returned in shallow. Files matched
// by no rule are returned in unmatched.
func (cfg *Config) Match(files []string) (units []*Unit, shallow map[string]*Rule, unmatched []string) {
	byKey := map[string]*Unit{}
	shallow = map[string]*Rule{}
	for _, f := range files {
		f = NormalizeFile(f)
		if f == "" || f == "." {
			continue
		}
		rule := cfg.ruleFor(f)
		if rule == nil {
			unmatched = append(unmatched, f)
			continue
		}
		rest := strings.TrimPrefix(f, rule.Path)
		parts := strings.Split(rest, "/")
		depth := rule.GetDepth()
		// The file must be at least depth+1 deep (depth dirs plus the file).
		if len(parts) <= depth {
			shallow[f] = rule
			continue
		}
		segments := parts[:depth]
		owned := rule.Path
		if depth > 0 {
			owned = rule.Path + strings.Join(segments, "/") + "/"
		}
		key := rule.Label() + "::" + owned
		u, ok := byKey[key]
		if !ok {
			u = &Unit{Rule: rule, Path: owned, Segments: segments}
			byKey[key] = u
			units = append(units, u)
		}
		u.Files = append(u.Files, f)
	}
	sort.Slice(units, func(i, j int) bool { return units[i].Path < units[j].Path })
	sort.Strings(unmatched)
	return units, shallow, unmatched
}

// ruleFor returns the first rule whose path prefix matches the file.
func (cfg *Config) ruleFor(file string) *Rule {
	for _, r := range cfg.Rules {
		if r.Path == "" || strings.HasPrefix(file, r.Path) {
			return r
		}
	}
	return nil
}
