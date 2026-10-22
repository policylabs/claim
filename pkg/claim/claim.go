// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package claim decides whether a pull request may change the paths it
// touches. For every owned path the change reaches, it loads the policy the
// repository configured for it, asks the path owner for the context values
// the policy leaves open and evaluates the policy with AMPEL against every
// commit in the range that touched the path.
package claim

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	intoto "github.com/in-toto/attestation/go/v1"
	acontext "github.com/policylabs/ampel/pkg/context"
	"github.com/policylabs/ampel/pkg/verifier"
	"github.com/policylabs/collector"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/claim/pkg/config"
	"github.com/policylabs/claim/pkg/material"
	"github.com/policylabs/claim/pkg/owner"
	"github.com/policylabs/claim/pkg/repo"
)

// Status of a unit or commit evaluation.
type Status string

const (
	// StatusPass means the policy passed.
	StatusPass Status = "PASS"
	// StatusFail means the policy failed.
	StatusFail Status = "FAIL"
	// StatusNoOwner means the owner could not be determined.
	StatusNoOwner Status = "NO_OWNER"
	// StatusMissingContext means required values were not supplied.
	StatusMissingContext Status = "MISSING_CONTEXT"
	// StatusError means the evaluation could not run.
	StatusError Status = "ERROR"
	// StatusAllowedUnchecked means the rule chose to allow a unit that could
	// not be fully evaluated (onMissingOwner: allow).
	StatusAllowedUnchecked Status = "ALLOWED_UNCHECKED"
)

// Options configure a check run.
type Options struct {
	// RepoDir is the local checkout of the repository receiving the change.
	RepoDir string
	// Base is the revision of the merge target (eg origin/main).
	Base string
	// Head is the revision of the pull request head commit. The range
	// evaluated is merge-base(base, head)..head.
	Head string
	// ConfigPath is the repository-relative configuration file.
	ConfigPath string
	// RepoLocator is the git+https locator (or file:// URL) of the repository
	// the collectors read evidence from. Derived from the origin remote when
	// empty.
	RepoLocator string
	// Collectors are extra AMPEL collector init strings added to every rule.
	Collectors []string
	// NoDefaultCollectors disables the gitsign and git notes collectors.
	NoDefaultCollectors bool
	// AttestationFiles are attestations handed to AMPEL directly. Unsigned
	// files are admitted, so this is for local experimentation and tests.
	AttestationFiles []string
	// ContextProviders supply context values locally (eg the environment).
	// They take precedence over the owner document.
	ContextProviders []acontext.Provider
	// Fetcher downloads owner documents. A strict default is used when nil.
	Fetcher *owner.Fetcher
	// VerifyPolicySignatures verifies signed policy material.
	VerifyPolicySignatures bool
	// Timeout for the whole run.
	Timeout time.Duration
}

// Report is the outcome of a check.
type Report struct {
	Repository string        `json:"repository,omitempty"`
	Base       string        `json:"base"`
	MergeBase  string        `json:"mergeBase"`
	Head       string        `json:"head"`
	Commits    []string      `json:"commits"`
	Files      []string      `json:"files"`
	Units      []*UnitResult `json:"units"`
	Unmatched  []string      `json:"unmatched,omitempty"`
	Shallow    []string      `json:"shallow,omitempty"`
	Allowed    bool          `json:"allowed"`
	Reasons    []string      `json:"reasons,omitempty"`
}

// UnitResult is the outcome for one owned path over the whole range.
type UnitResult struct {
	Rule         string          `json:"rule"`
	Path         string          `json:"path"`
	Files        []string        `json:"files"`
	Policy       string          `json:"policy"`
	Owner        string          `json:"owner,omitempty"`
	OwnerSource  string          `json:"ownerSource,omitempty"`
	OwnerContext []string        `json:"ownerContext,omitempty"`
	Status       Status          `json:"status"`
	Allowed      bool            `json:"allowed"`
	Message      string          `json:"message,omitempty"`
	Commits      []*CommitResult `json:"commits,omitempty"`
}

// CommitResult is the policy verdict for one commit touching a unit.
type CommitResult struct {
	Commit  string       `json:"commit"`
	Files   []string     `json:"files"`
	Status  Status       `json:"status"`
	Message string       `json:"message,omitempty"`
	Results papi.Results `json:"results,omitempty"`
}

// Checker runs checks.
type Checker struct {
	Options Options
}

// New returns a checker.
func New(opts *Options) *Checker {
	if opts.ConfigPath == "" {
		opts.ConfigPath = config.DefaultFileName
	}
	if opts.Fetcher == nil {
		opts.Fetcher = &owner.Fetcher{}
	}
	if opts.RepoDir == "" {
		opts.RepoDir = "."
	}
	return &Checker{Options: *opts}
}

// unitWork collects, per owned path, the commits that touched it.
type unitWork struct {
	unit    *config.Unit
	commits []*commitWork
}

type commitWork struct {
	commit *object.Commit
	files  []string
}

// Run performs the check.
func (c *Checker) Run(ctx context.Context) (*Report, error) {
	if c.Options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Options.Timeout)
		defer cancel()
	}
	if c.Options.Base == "" || c.Options.Head == "" {
		return nil, errors.New("base and head revisions are required")
	}

	r, err := repo.Open(c.Options.RepoDir)
	if err != nil {
		return nil, err
	}
	base, err := r.ResolveCommit(c.Options.Base)
	if err != nil {
		return nil, fmt.Errorf("resolving base: %w", err)
	}
	head, err := r.ResolveCommit(c.Options.Head)
	if err != nil {
		return nil, fmt.Errorf("resolving head: %w", err)
	}
	mergeBase, err := r.MergeBase(base, head)
	if err != nil {
		return nil, err
	}

	// Everything claim trusts comes from the base commit: the configuration,
	// repository-local policies and owner pointer files. The range only
	// contributes the subjects (commit hashes) and the files each touched.
	readBase := func(path string) ([]byte, error) { return repo.ReadFile(base, path) }

	cfgData, err := readBase(c.Options.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading configuration from base %s: %w", base.Hash, err)
	}
	cfg, err := config.Parse(cfgData)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", c.Options.ConfigPath, err)
	}

	commits, err := r.CommitsInRange(mergeBase, head)
	if err != nil {
		return nil, err
	}

	locator := c.Options.RepoLocator
	if locator == "" {
		locator = LocatorFromRemote(r.RemoteURL("origin"), r.Dir())
	}
	slug := SlugFromLocator(locator)

	report := &Report{
		Repository: slug,
		Base:       base.Hash.String(),
		MergeBase:  mergeBase.Hash.String(),
		Head:       head.Hash.String(),
		Allowed:    true,
	}
	if len(commits) == 0 {
		report.Reasons = append(report.Reasons, "no commits in range")
		return report, nil
	}

	// Group the files every commit touched into owned units.
	work := map[string]*unitWork{}
	order := []string{}
	allFiles := map[string]struct{}{}
	unmatched := map[string]struct{}{}
	shallow := map[string]*config.Rule{}
	for _, commit := range commits {
		report.Commits = append(report.Commits, commit.Hash.String())
		files, err := repo.CommitChanges(commit)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			logrus.Debugf("commit %s changes no paths on its own, skipping", commit.Hash)
			continue
		}
		units, sh, um := cfg.Match(files)
		for _, f := range files {
			allFiles[f] = struct{}{}
		}
		for _, f := range um {
			unmatched[f] = struct{}{}
		}
		for f, rule := range sh {
			shallow[f] = rule
		}
		for _, u := range units {
			w, ok := work[u.Key()]
			if !ok {
				w = &unitWork{unit: &config.Unit{Rule: u.Rule, Path: u.Path, Segments: u.Segments}}
				work[u.Key()] = w
				order = append(order, u.Key())
			}
			w.commits = append(w.commits, &commitWork{commit: commit, files: u.Files})
			w.unit.Files = appendUnique(w.unit.Files, u.Files...)
		}
	}
	sort.Strings(order)
	report.Files = sortedKeys(allFiles)
	report.Unmatched = sortedKeys(unmatched)
	for f := range shallow {
		report.Shallow = append(report.Shallow, f)
	}
	sort.Strings(report.Shallow)

	if len(report.Unmatched) > 0 && cfg.Unmatched != config.Allow {
		report.Allowed = false
		report.Reasons = append(report.Reasons, fmt.Sprintf("%d changed file(s) match no rule and unmatched is %s", len(report.Unmatched), cfg.Unmatched))
	}
	for f, rule := range shallow {
		if rule.OnMissingOwner == config.Allow {
			continue
		}
		report.Allowed = false
		report.Reasons = append(report.Reasons, fmt.Sprintf("%s is under rule %s but has no owner segment", f, rule.Label()))
	}
	sort.Strings(report.Reasons)

	for _, key := range order {
		res := c.evaluateUnit(ctx, work[key], readBase, locator, slug)
		report.Units = append(report.Units, res)
		if !res.Allowed {
			report.Allowed = false
			report.Reasons = append(report.Reasons, fmt.Sprintf("%s: %s", res.Path, res.Message))
		}
	}
	return report, nil
}

// evaluateUnit resolves the policy and owner of one owned path once, then
// evaluates the policy against every commit that touched the path. It never
// returns an error: anything that prevents a verdict denies the unit.
func (c *Checker) evaluateUnit(
	ctx context.Context, w *unitWork, readBase owner.FileReader, locator, slug string,
) *UnitResult {
	unit := w.unit
	rule := unit.Rule
	res := &UnitResult{
		Rule:   rule.Label(),
		Path:   unit.Path,
		Files:  unit.Files,
		Policy: rule.Policy,
	}
	fail := func(status Status, format string, args ...any) *UnitResult {
		res.Status = status
		res.Allowed = false
		res.Message = fmt.Sprintf(format, args...)
		return res
	}

	mat, err := material.Load(rule.Policy, material.FileReader(readBase), c.Options.VerifyPolicySignatures)
	if err != nil {
		return fail(StatusError, "loading policy: %v", err)
	}

	providers := append([]acontext.Provider{}, c.Options.ContextProviders...)

	// Resolve the owner and fetch its document.
	var ownerUnavailable error
	if rule.Owner.Scheme != config.SchemeNone {
		p, o, err := c.ownerProvider(ctx, unit, mat, readBase, slug)
		if o != nil {
			res.Owner = o.String()
			res.OwnerSource = o.Source
		}
		if err != nil {
			ownerUnavailable = err
		} else {
			res.OwnerContext = p.Keys()
			// Local providers come first: the repository always wins over
			// the owner when both define a value.
			providers = append(providers, p)
		}
	}

	// Every required open value must now be resolvable, otherwise AMPEL
	// cannot evaluate. Check before running so the report says what is
	// missing rather than surfacing an evaluation error.
	required := mat.RequiredOpen()
	have, err := acontext.GetValues(providers, required)
	if err != nil {
		return fail(StatusError, "reading context providers: %v", err)
	}
	missing := []string{}
	for _, k := range required {
		if v, ok := have[k]; !ok || v == nil {
			missing = append(missing, k)
		}
	}

	if ownerUnavailable != nil {
		if rule.OnMissingOwner == config.Allow {
			if len(missing) > 0 {
				res.Status = StatusAllowedUnchecked
				res.Allowed = true
				res.Message = fmt.Sprintf("owner unavailable (%v); allowed without evaluation by onMissingOwner: allow", ownerUnavailable)
				logrus.Warnf("%s: %s", unit.Path, res.Message)
				return res
			}
			logrus.Warnf("%s: owner unavailable (%v); evaluating with local context only", unit.Path, ownerUnavailable)
		} else {
			return fail(StatusNoOwner, "%v", ownerUnavailable)
		}
	}
	if len(missing) > 0 {
		return fail(StatusMissingContext, "required context values not supplied: %s", strings.Join(missing, ", "))
	}

	// Build the verifier with the evidence collectors.
	if err := collector.LoadDefaultRepositoryTypes(); err != nil {
		return fail(StatusError, "loading collector types: %v", err)
	}
	inits := []string{}
	if !c.Options.NoDefaultCollectors && locator != "" {
		inits = append(inits, "gitsign:"+locator, "dnote:"+locator)
	}
	inits = append(inits, rule.Collectors...)
	inits = append(inits, c.Options.Collectors...)
	ampel, err := verifier.New(verifier.WithCollectorInits(inits))
	if err != nil {
		return fail(StatusError, "creating verifier: %v", err)
	}

	vopts := verifier.NewVerificationOptions()
	vopts.ContextProviders = providers
	vopts.AttestationFiles = c.Options.AttestationFiles
	vopts.AdmitUnverified = len(c.Options.AttestationFiles) > 0
	vopts.AttestResults = false

	// A path passes only when every commit that touched it passes.
	res.Status = StatusPass
	res.Allowed = true
	failed := 0
	for _, cw := range w.commits {
		cr := &CommitResult{Commit: cw.commit.Hash.String(), Files: cw.files}
		res.Commits = append(res.Commits, cr)
		subject := &intoto.ResourceDescriptor{
			Name: strings.TrimPrefix(slug+"@"+cw.commit.Hash.String(), "@"),
			Digest: map[string]string{
				intoto.AlgorithmGitCommit.String(): cw.commit.Hash.String(),
				intoto.AlgorithmSHA1.String():      cw.commit.Hash.String(),
			},
		}
		results, err := ampel.Verify(ctx, &vopts, mat.Object(), subject)
		switch {
		case err != nil:
			cr.Status = StatusError
			cr.Message = fmt.Sprintf("evaluating policy %s: %v", mat.ID(), err)
		case results.GetStatus() == papi.StatusPASS:
			cr.Status = StatusPass
			cr.Results = results
			cr.Message = fmt.Sprintf("policy %s passed", mat.ID())
		default:
			cr.Status = StatusFail
			cr.Results = results
			cr.Message = fmt.Sprintf("policy %s returned %s: %s", mat.ID(), results.GetStatus(), failureSummary(results))
		}
		if cr.Status != StatusPass {
			failed++
			res.Status = cr.Status
			res.Allowed = false
		}
	}
	if failed == 0 {
		res.Message = fmt.Sprintf("policy %s passed on %d commit(s)", mat.ID(), len(w.commits))
		return res
	}
	if failed > 1 {
		res.Status = StatusFail
	}
	msgs := []string{}
	for _, cr := range res.Commits {
		if cr.Status != StatusPass {
			msgs = append(msgs, fmt.Sprintf("%s: %s", short(cr.Commit), cr.Message))
		}
	}
	res.Message = fmt.Sprintf("%d of %d commit(s) failed: %s", failed, len(w.commits), strings.Join(msgs, "; "))
	return res
}

// ownerProvider resolves the owner of a unit, fetches and checks its document
// and wraps the values that apply as a filtered context provider.
func (c *Checker) ownerProvider(
	ctx context.Context, unit *config.Unit, mat *material.Material, readBase owner.FileReader, slug string,
) (*owner.Provider, *owner.Owner, error) {
	rule := unit.Rule
	o, err := owner.Resolve(unit, readBase)
	if err != nil {
		return nil, nil, err
	}
	data, err := c.Options.Fetcher.Fetch(ctx, o)
	if err != nil {
		return nil, o, fmt.Errorf("%w: %w", owner.ErrNoOwner, err)
	}
	if err := owner.VerifyDigest(data, rule.Owner.Digests); err != nil {
		return nil, o, fmt.Errorf("%w: %s: %w", owner.ErrNoOwner, o, err)
	}
	doc, err := owner.ParseDocument(data)
	if err != nil {
		return nil, o, fmt.Errorf("%w: %s: %w", owner.ErrNoOwner, o, err)
	}
	fillable := mat.OwnerFillable(rule.OwnerContext)
	values := doc.ContextFor(slug, unit.Path)
	p, err := owner.NewProvider(values, fillable)
	if err != nil {
		return nil, o, fmt.Errorf("%w: %s: %w", owner.ErrNoOwner, o, err)
	}
	for k := range values {
		if _, ok := values[k]; ok && !contains(fillable, k) {
			logrus.Warnf("%s: owner document %s supplies %q, which the policy does not leave open; ignored", unit.Path, o, k)
		}
	}
	return p, o, nil
}

// failureSummary extracts the error messages of failed tenets.
func failureSummary(results papi.Results) string {
	msgs := []string{}
	addResult := func(r *papi.Result) {
		if r == nil {
			return
		}
		for _, er := range r.GetEvalResults() {
			if er.GetStatus() == papi.StatusPASS {
				continue
			}
			if m := er.GetError().GetMessage(); m != "" {
				msgs = append(msgs, m)
			}
		}
	}
	addGroup := func(g *papi.ResultGroup) {
		if g == nil {
			return
		}
		if g.GetError() != "" {
			msgs = append(msgs, g.GetError())
		}
		for _, b := range g.GetEvalResults() {
			if m := b.GetError().GetMessage(); m != "" {
				msgs = append(msgs, m)
			}
			for _, r := range b.GetResults() {
				addResult(r)
			}
		}
	}
	switch v := results.(type) {
	case *papi.Result:
		addResult(v)
	case *papi.ResultSet:
		if m := v.GetError().GetMessage(); m != "" {
			msgs = append(msgs, m)
		}
		for _, r := range v.GetResults() {
			addResult(r)
		}
		for _, g := range v.GetGroups() {
			addGroup(g)
		}
	case *papi.ResultGroup:
		addGroup(v)
	}
	if len(msgs) == 0 {
		return "no details"
	}
	return strings.Join(msgs, "; ")
}

// LocatorFromRemote converts a git remote URL into the locator the collectors
// take: git+https://host/org/repo. Unknown shapes fall back to a file://
// locator for the local directory.
func LocatorFromRemote(remote, dir string) string {
	if loc := remoteToLocator(remote); loc != "" {
		return loc
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	return "file://" + filepath.ToSlash(abs)
}

func remoteToLocator(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	// scp-like: git@github.com:org/repo.git
	if !strings.Contains(remote, "://") {
		if i := strings.Index(remote, "@"); i >= 0 {
			rest := remote[i+1:]
			if j := strings.Index(rest, ":"); j > 0 {
				return "git+https://" + rest[:j] + "/" + strings.TrimSuffix(strings.TrimPrefix(rest[j+1:], "/"), ".git")
			}
		}
		return ""
	}
	u, err := url.Parse(remote)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "https", "http", "ssh", "git", "git+https", "git+ssh":
		return "git+https://" + u.Hostname() + "/" + strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	}
	return ""
}

// SlugFromLocator returns host/org/repo for a git+https locator, or "" for
// local repositories.
func SlugFromLocator(locator string) string {
	l := strings.TrimPrefix(locator, "git+")
	u, err := url.Parse(l)
	if err != nil || u.Scheme == "file" || u.Host == "" {
		return ""
	}
	p := strings.Trim(u.Path, "/")
	if i := strings.Index(p, "@"); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(u.Hostname() + "/" + strings.TrimSuffix(p, ".git"))
}

func appendUnique(dst []string, items ...string) []string {
	for _, it := range items {
		if !contains(dst, it) {
			dst = append(dst, it)
		}
	}
	sort.Strings(dst)
	return dst
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
