// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	acontext "github.com/policylabs/ampel/pkg/context"
	"github.com/spf13/cobra"

	"github.com/policylabs/claim/pkg/claim"
	"github.com/policylabs/claim/pkg/config"
	"github.com/policylabs/claim/pkg/owner"
)

// Exit codes of claim check.
const (
	ExitAllowed = 0
	ExitDenied  = 1
	ExitError   = 2
)

type checkOptions struct {
	claim.Options
	format       string
	allowPrivate bool
	contextEnv   bool
	contextJSON  string
	contextYAML  string
	exitCode     bool
	timeout      time.Duration
}

func newCheckCommand() *cobra.Command {
	opts := &checkOptions{}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "check whether a change may touch the paths it modifies",
		Long: `Check evaluates every commit between the merge target (--base) and the pull
request head (--head): each owned path a commit touches is gated by the policy
the repository configured for it, and a path passes only when every commit
that touched it passes.

The configuration (.claim.yaml), repository-local policies and owner pointer
files are always read from the base commit, so a pull request can never alter
the rules it is judged by. Each commit is the subject the policy is evaluated
against: by default claim looks for its gitsign signature and for attestations
stored in git notes.

In GitHub Actions, check out the pull request head commit (not the synthetic
merge commit) with full history and run:

  claim check --base origin/$GITHUB_BASE_REF --head $PR_HEAD_SHA

Exit codes: 0 allowed, 1 denied, 2 error.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return opts.run(cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.RepoDir, "repo", "C", ".", "path to the repository checkout")
	f.StringVarP(&opts.Base, "base", "b", "", "merge target revision (eg origin/main)")
	f.StringVar(&opts.Head, "head", "HEAD", "pull request head commit")
	f.StringVar(&opts.ConfigPath, "config", config.DefaultFileName, "configuration file, relative to the repository root (read from base)")
	f.StringVar(&opts.RepoLocator, "locator", "", "git+https locator of the repository for evidence collectors (default: derived from the origin remote)")
	f.StringSliceVarP(&opts.Collectors, "collector", "c", nil, "additional AMPEL collector init strings")
	f.BoolVar(&opts.NoDefaultCollectors, "no-default-collectors", false, "do not add the gitsign and git notes collectors")
	f.StringSliceVarP(&opts.AttestationFiles, "attestation", "a", nil, "attestation files to admit unsigned (local experimentation only)")
	f.BoolVar(&opts.VerifyPolicySignatures, "policy-verify", true, "verify signed policies")
	f.StringVarP(&opts.format, "format", "f", "text", "output format (text, json)")
	f.BoolVar(&opts.allowPrivate, "allow-private-owners", false, "DANGEROUS: fetch owner documents from private, local or plain-http locations (tests only)")
	f.BoolVar(&opts.contextEnv, "context-env", false, "read context values from AMPEL_* environment variables")
	f.StringVar(&opts.contextJSON, "context-json", "", "JSON object with local context values, or @file")
	f.StringVar(&opts.contextYAML, "context-yaml", "", "YAML document with local context values, or @file")
	f.BoolVar(&opts.exitCode, "exit-code", true, "exit 1 when the change is denied")
	f.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "overall timeout")
	return cmd
}

func (o *checkOptions) run(w io.Writer) error {
	if o.Base == "" {
		return errors.New("--base is required")
	}
	switch o.format {
	case "text", "json":
	default:
		return fmt.Errorf("unknown output format %q", o.format)
	}
	providers, err := o.localProviders()
	if err != nil {
		return err
	}
	o.ContextProviders = providers
	o.Fetcher = &owner.Fetcher{AllowPrivate: o.allowPrivate}
	o.Timeout = o.timeout

	report, err := claim.New(&o.Options).Run(contextWithSignals())
	if err != nil {
		return err
	}
	if o.format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encoding report: %w", err)
		}
	} else {
		renderText(w, report)
	}
	if !report.Allowed && o.exitCode {
		os.Exit(ExitDenied)
	}
	return nil
}

func (o *checkOptions) localProviders() ([]acontext.Provider, error) {
	providers := []acontext.Provider{}
	load := func(spec string, fromFile func(string) (acontext.Provider, error), fromString func(io.Reader) (acontext.Provider, error)) error {
		if spec == "" {
			return nil
		}
		var p acontext.Provider
		var err error
		if path, ok := strings.CutPrefix(spec, "@"); ok {
			p, err = fromFile(path)
		} else {
			p, err = fromString(strings.NewReader(spec))
		}
		if err != nil {
			return err
		}
		providers = append(providers, p)
		return nil
	}
	if err := load(o.contextJSON, acontext.NewProviderFromJSONFile, acontext.NewProviderFromJSON); err != nil {
		return nil, fmt.Errorf("loading JSON context: %w", err)
	}
	if err := load(o.contextYAML, acontext.NewProviderFromYAMLFile, acontext.NewProviderFromYAML); err != nil {
		return nil, fmt.Errorf("loading YAML context: %w", err)
	}
	if o.contextEnv {
		providers = append(providers, acontext.NewEnvContextReader())
	}
	return providers, nil
}

func renderText(w io.Writer, r *claim.Report) {
	out := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) } //nolint:errcheck // best-effort console output

	out("claim: %s → %s (merge base %s)\n", short(r.Base), short(r.Head), short(r.MergeBase))
	if r.Repository != "" {
		out("repository: %s\n", r.Repository)
	}
	out("commits: %d, changed files: %d\n\n", len(r.Commits), len(r.Files))
	for _, u := range r.Units {
		mark := "✗"
		if u.Allowed {
			mark = "✓"
		}
		out("%s %s  [%s]  rule %s\n", mark, u.Path, u.Status, u.Rule)
		out("    policy: %s\n", u.Policy)
		if u.Owner != "" {
			out("    owner:  %s (%s)\n", u.Owner, u.OwnerSource)
		}
		if len(u.OwnerContext) > 0 {
			out("    owner supplied: %s\n", strings.Join(u.OwnerContext, ", "))
		}
		for _, f := range u.Files {
			out("    - %s\n", f)
		}
		for _, cr := range u.Commits {
			cmark := "✗"
			if cr.Status == claim.StatusPass {
				cmark = "✓"
			}
			out("    %s %s [%s] %s\n", cmark, short(cr.Commit), cr.Status, cr.Message)
		}
		if u.Message != "" && len(u.Commits) != 1 {
			out("    %s\n", u.Message)
		}
	}
	if len(r.Shallow) > 0 {
		out("\nfiles with no owner segment:\n")
		for _, f := range r.Shallow {
			out("    - %s\n", f)
		}
	}
	if len(r.Unmatched) > 0 {
		out("\nfiles matching no rule:\n")
		for _, f := range r.Unmatched {
			out("    - %s\n", f)
		}
	}
	out("\n")
	if r.Allowed {
		out("RESULT: ALLOWED\n")
	} else {
		out("RESULT: DENIED\n")
		for _, reason := range r.Reasons {
			out("  - %s\n", reason)
		}
	}
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
