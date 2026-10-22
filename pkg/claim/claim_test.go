// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package claim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/claim/pkg/owner"
)

const (
	testConfig = `
version: 1
rules:
  - name: registry
    path: data/
    policy: policies/author.json
    owner:
      scheme: host
  - name: vendors
    path: vendor/
    policy: policies/author.json
    owner:
      scheme: file
      file: config.json
      pointer: /owner
  - name: docs
    path: docs/
    policy: policies/author.json
`

	// The test policy stands in for a commit signature policy: the owner
	// supplies the list of accepted authors through the signers context
	// value and the tenet checks the attested author against it.
	testPolicy = `{
  "id": "author-in-signers",
  "context": {"signers": {"required": true}},
  "predicates": {"types": ["https://claim.test/author/v1"]},
  "tenets": [{
    "id": "author-allowed",
    "code": "predicates.exists(p, has(p.data.author) && p.data.author in context.signers)",
    "error": {"message": "author is not an accepted signer"}
  }]
}`
)

// routeTransport sends every request to the test server and records hosts.
type routeTransport struct {
	target *url.URL
	mu     sync.Mutex
	hosts  []string
}

func (rt *routeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.hosts = append(rt.hosts, req.URL.Host)
	rt.mu.Unlock()
	r2 := req.Clone(req.Context())
	r2.URL.Scheme = rt.target.Scheme
	r2.URL.Host = rt.target.Host
	r2.Host = req.URL.Host // the server routes by the original host
	return http.DefaultTransport.RoundTrip(r2)
}

// ownerServer serves owner documents by host.
type ownerServer struct {
	mu   sync.Mutex
	docs map[string]string
}

func (s *ownerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	doc, ok := s.docs[r.Host]
	s.mu.Unlock()
	if !ok || r.URL.Path != "/.well-known/claim.yaml" {
		http.NotFound(w, r)
		return
	}
	if _, err := io.WriteString(w, doc); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *ownerServer) set(host, doc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[host] = doc
}

func commitFiles(t *testing.T, r *git.Repository, dir, msg string, files map[string]string) plumbing.Hash {
	t.Helper()
	wt, err := r.Worktree()
	require.NoError(t, err)
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
		_, err = wt.Add(name)
		require.NoError(t, err)
	}
	h, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	return h
}

// fixture builds the registry repository with a base commit and a PR branch.
type fixture struct {
	dir    string
	repo   *git.Repository
	base   plumbing.Hash
	server *ownerServer
	rt     *routeTransport
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	base := commitFiles(t, r, dir, "base", map[string]string{
		".claim.yaml":              testConfig,
		"policies/author.json":     testPolicy,
		"data/owner.example/a.txt": "a",
		"vendor/acme/config.json":  `{"owner": "https://acme.example"}`,
		"vendor/acme/lib.txt":      "v1",
		"docs/index.md":            "docs",
	})
	srv := &ownerServer{docs: map[string]string{}}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	target, err := url.Parse(hs.URL)
	require.NoError(t, err)
	return &fixture{dir: dir, repo: r, base: base, server: srv, rt: &routeTransport{target: target}}
}

// pr creates a branch from base with the given changes and returns its head.
func (f *fixture) pr(t *testing.T, name string, files map[string]string) plumbing.Hash {
	t.Helper()
	wt, err := f.repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Hash: f.base}))
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName(name), Create: true}))
	return f.commit(t, name, files)
}

// commit adds a commit with the given changes on the current branch.
func (f *fixture) commit(t *testing.T, msg string, files map[string]string) plumbing.Hash {
	t.Helper()
	// Keep commit timestamps strictly increasing so range ordering is stable.
	time.Sleep(1100 * time.Millisecond)
	return commitFiles(t, f.repo, f.dir, msg, files)
}

// attestations writes one unsigned author statement per commit.
func (f *fixture) attestations(t *testing.T, authors map[plumbing.Hash]string) []string {
	t.Helper()
	dir := t.TempDir()
	files := make([]string, 0, len(authors))
	for h, author := range authors {
		p := filepath.Join(dir, h.String()+".json")
		require.NoError(t, os.WriteFile(p, []byte(fmt.Sprintf(`{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"digest": {"sha1": "%s"}}],
  "predicateType": "https://claim.test/author/v1",
  "predicate": {"author": "%s"}
}`, h, author)), 0o600))
		files = append(files, p)
	}
	return files
}

// attestation writes an unsigned statement about one commit.
func (f *fixture) attestation(t *testing.T, head plumbing.Hash, author string) []string {
	t.Helper()
	return f.attestations(t, map[plumbing.Hash]string{head: author})
}

func (f *fixture) run(t *testing.T, head plumbing.Hash, atts []string) *Report {
	t.Helper()
	opts := Options{
		RepoDir:             f.dir,
		Base:                f.base.String(),
		Head:                head.String(),
		NoDefaultCollectors: true,
		Fetcher:             &owner.Fetcher{Transport: f.rt},
		RepoLocator:         "git+https://github.com/org/registry",
		AttestationFiles:    atts,
	}
	report, err := New(&opts).Run(context.Background())
	require.NoError(t, err)
	return report
}

func unit(t *testing.T, r *Report, path string) *UnitResult {
	t.Helper()
	for _, u := range r.Units {
		if u.Path == path {
			return u
		}
	}
	t.Fatalf("unit %s not in report: %+v", path, r.Units)
	return nil
}

func TestCheckOwnersDecide(t *testing.T) {
	f := newFixture(t)
	f.server.set("owner.example", "version: 1\ncontext: {signers: [alice@example.com]}\n")
	f.server.set("acme.example", "version: 1\ncontext: {signers: [bob@example.com]}\n")

	head := f.pr(t, "change", map[string]string{
		"data/owner.example/a.txt": "changed",
		"vendor/acme/lib.txt":      "v2",
	})
	report := f.run(t, head, f.attestation(t, head, "alice@example.com"))

	require.False(t, report.Allowed)
	require.Equal(t, "github.com/org/registry", report.Repository)
	require.Len(t, report.Units, 2)
	require.Equal(t, []string{head.String()}, report.Commits)

	u := unit(t, report, "data/owner.example/")
	require.Equal(t, StatusPass, u.Status)
	require.True(t, u.Allowed)
	require.Equal(t, "https://owner.example/.well-known/claim.yaml", u.Owner)
	require.Equal(t, []string{"signers"}, u.OwnerContext)

	u = unit(t, report, "vendor/acme/")
	require.Equal(t, StatusFail, u.Status)
	require.False(t, u.Allowed)
	require.Contains(t, u.Message, "author is not an accepted signer")
	require.Equal(t, "https://acme.example/.well-known/claim.yaml", u.Owner)
	require.Len(t, u.Commits, 1)
	require.Equal(t, StatusFail, u.Commits[0].Status)
	require.NotNil(t, u.Commits[0].Results)

	// Once acme accepts alice, the whole change goes through.
	f.server.set("acme.example", "version: 1\ncontext: {signers: [bob@example.com, alice@example.com]}\n")
	report = f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.True(t, report.Allowed, report.Reasons)
	require.Equal(t, StatusPass, unit(t, report, "vendor/acme/").Status)
}

func TestCheckOwnerDocumentScoping(t *testing.T) {
	f := newFixture(t)
	// The owner narrows the signers for this repository and path.
	f.server.set("owner.example", `
version: 1
context: {signers: [alice@example.com]}
repositories:
  github.com/org/registry:
    paths:
      data/owner.example/:
        context: {signers: [carol@example.com]}
`)
	head := f.pr(t, "scoped", map[string]string{"data/owner.example/a.txt": "x"})
	report := f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.False(t, report.Allowed)
	report = f.run(t, head, f.attestation(t, head, "carol@example.com"))
	require.True(t, report.Allowed, report.Reasons)
}

func TestCheckRulesComeFromBase(t *testing.T) {
	f := newFixture(t)
	f.server.set("owner.example", "version: 1\ncontext: {signers: [alice@example.com]}\n")
	f.server.set("evil.example", "version: 1\ncontext: {signers: [mallory@example.com]}\n")

	// The PR rewrites the rules, the policy and the owner pointer file to
	// let itself through. None of it may count.
	head := f.pr(t, "tamper", map[string]string{
		".claim.yaml":              "version: 1\nunmatched: allow\nrules: [{path: nothing/, policy: policies/author.json}]\n",
		"policies/author.json":     `{"id": "open", "predicates": {"types": ["https://claim.test/author/v1"]}, "tenets": [{"id": "t", "code": "true"}]}`,
		"vendor/acme/config.json":  `{"owner": "https://evil.example"}`,
		"vendor/acme/lib.txt":      "pwned",
		"data/owner.example/a.txt": "changed",
		"unrelated.txt":            "x",
	})
	report := f.run(t, head, f.attestation(t, head, "mallory@example.com"))
	require.False(t, report.Allowed)
	// The unmatched decision is the base one: deny.
	require.ElementsMatch(t, []string{".claim.yaml", "policies/author.json", "unrelated.txt"}, report.Unmatched)
	// The owner pointer was read from base, so acme.example (no document
	// served) is the owner, not evil.example.
	u := unit(t, report, "vendor/acme/")
	require.Equal(t, StatusNoOwner, u.Status)
	require.Equal(t, "https://acme.example/.well-known/claim.yaml", u.Owner)
	// The base policy still requires an accepted signer.
	u = unit(t, report, "data/owner.example/")
	require.Equal(t, StatusFail, u.Status)
	for _, h := range f.rt.hosts {
		require.NotEqual(t, "evil.example", h)
	}
}

func TestCheckMissingOwner(t *testing.T) {
	f := newFixture(t)
	head := f.pr(t, "noowner", map[string]string{"data/owner.example/a.txt": "x"})
	report := f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.False(t, report.Allowed)
	u := unit(t, report, "data/owner.example/")
	require.Equal(t, StatusNoOwner, u.Status)
	require.Contains(t, u.Message, "404")

	// A malformed owner document is the same as no owner.
	f.server.set("owner.example", "version: 1\nunknown: field\n")
	report = f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.Equal(t, StatusNoOwner, unit(t, report, "data/owner.example/").Status)

	// An invalid host segment never reaches the network.
	head = f.pr(t, "badhost", map[string]string{"data/localhost/a.txt": "x"})
	report = f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.Equal(t, StatusNoOwner, unit(t, report, "data/localhost/").Status)
	for _, h := range f.rt.hosts {
		require.NotEqual(t, "localhost", h)
	}
}

func TestCheckMissingContextWithoutOwner(t *testing.T) {
	f := newFixture(t)
	// The docs rule has no owner and nothing supplies signers locally.
	head := f.pr(t, "docs", map[string]string{"docs/index.md": "new"})
	report := f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.False(t, report.Allowed)
	u := unit(t, report, "docs/")
	require.Equal(t, StatusMissingContext, u.Status)
	require.Contains(t, u.Message, "signers")
}

func TestCheckShallowAndNoChanges(t *testing.T) {
	f := newFixture(t)
	head := f.pr(t, "shallow", map[string]string{"data/README.md": "readme"})
	report := f.run(t, head, nil)
	require.False(t, report.Allowed)
	require.Equal(t, []string{"data/README.md"}, report.Shallow)
	require.Empty(t, report.Units)

	report = f.run(t, f.base, nil)
	require.True(t, report.Allowed)
	require.Empty(t, report.Files)
	require.Empty(t, report.Commits)
}

func TestCheckEveryCommitMustPass(t *testing.T) {
	f := newFixture(t)
	f.server.set("owner.example", "version: 1\ncontext: {signers: [alice@example.com]}\n")

	first := f.pr(t, "multi", map[string]string{"data/owner.example/a.txt": "by alice"})
	second := f.commit(t, "sneaky", map[string]string{"data/owner.example/b.txt": "by mallory"})
	third := f.commit(t, "fix", map[string]string{"data/owner.example/a.txt": "alice again"})

	// Alice signs the first and last commits, Mallory the middle one. The
	// head commit alone looks fine; the range does not.
	atts := f.attestations(t, map[plumbing.Hash]string{
		first:  "alice@example.com",
		second: "mallory@example.com",
		third:  "alice@example.com",
	})
	report := f.run(t, third, atts)
	require.False(t, report.Allowed)
	require.Equal(t, []string{first.String(), second.String(), third.String()}, report.Commits)
	u := unit(t, report, "data/owner.example/")
	require.Equal(t, StatusFail, u.Status)
	require.Len(t, u.Commits, 3)
	require.Equal(t, StatusPass, u.Commits[0].Status)
	require.Equal(t, StatusFail, u.Commits[1].Status)
	require.Equal(t, []string{"data/owner.example/b.txt"}, u.Commits[1].Files)
	require.Equal(t, StatusPass, u.Commits[2].Status)
	require.Contains(t, u.Message, "1 of 3 commit(s) failed")
	require.ElementsMatch(t, []string{"data/owner.example/a.txt", "data/owner.example/b.txt"}, u.Files)

	// A commit with no evidence at all fails too.
	report = f.run(t, third, f.attestations(t, map[plumbing.Hash]string{first: "alice@example.com", third: "alice@example.com"}))
	require.False(t, report.Allowed)
	require.Equal(t, StatusFail, unit(t, report, "data/owner.example/").Commits[1].Status)

	// With Mallory accepted by the owner everything passes.
	f.server.set("owner.example", "version: 1\ncontext: {signers: [alice@example.com, mallory@example.com]}\n")
	report = f.run(t, third, atts)
	require.True(t, report.Allowed, report.Reasons)
	require.Equal(t, StatusPass, unit(t, report, "data/owner.example/").Status)
}

func TestCheckPinnedDigest(t *testing.T) {
	f := newFixture(t)
	doc := "version: 1\ncontext: {signers: [alice@example.com]}\n"
	f.server.set("owner.example", doc)
	sum := sha256.Sum256([]byte(doc))
	cfg := strings.Replace(testConfig, "      scheme: host\n", "      scheme: host\n      digests: [sha256:"+hex.EncodeToString(sum[:])+"]\n", 1)
	require.NotEqual(t, testConfig, cfg)
	wt, err := f.repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Hash: f.base}))
	f.base = commitFiles(t, f.repo, f.dir, "pin", map[string]string{".claim.yaml": cfg})

	head := f.pr(t, "pinned", map[string]string{"data/owner.example/a.txt": "x"})
	report := f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.True(t, report.Allowed, report.Reasons)

	// The owner changes the document: the pin no longer matches.
	f.server.set("owner.example", doc+"# rotated\n")
	report = f.run(t, head, f.attestation(t, head, "alice@example.com"))
	require.False(t, report.Allowed)
	u := unit(t, report, "data/owner.example/")
	require.Equal(t, StatusNoOwner, u.Status)
	require.Contains(t, u.Message, "pinned digests")
}

func TestLocatorHelpers(t *testing.T) {
	t.Parallel()
	require.Equal(t, "git+https://github.com/org/repo", LocatorFromRemote("git@github.com:org/repo.git", "."))
	require.Equal(t, "git+https://github.com/org/repo", LocatorFromRemote("https://github.com/org/repo.git", "."))
	require.Equal(t, "git+https://github.com/org/repo", LocatorFromRemote("ssh://git@github.com/org/repo", "."))
	require.Contains(t, LocatorFromRemote("", "/tmp/x"), "file://")
	require.Equal(t, "github.com/org/repo", SlugFromLocator("git+https://github.com/org/repo@main"))
	require.Empty(t, SlugFromLocator("file:///tmp/x"))
}
