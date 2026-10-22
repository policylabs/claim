// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package repo gives claim read access to the git repository receiving the
// pull request: resolving the base and head commits, listing the files the
// change touches and reading trusted files from the merge target.
package repo

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// MaxFileSize caps the size of the files claim reads from the repository
// (configuration, policies, owner pointer files).
const MaxFileSize = 4 << 20

// ErrNotFound is returned when a file does not exist in a commit's tree.
var ErrNotFound = errors.New("file not found in commit")

// Repository wraps a local git checkout.
type Repository struct {
	repo *git.Repository
	dir  string
}

// Open opens the repository that contains dir.
func Open(dir string) (*Repository, error) {
	r, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("opening repository at %q: %w", dir, err)
	}
	return &Repository{repo: r, dir: dir}, nil
}

// Dir returns the directory the repository was opened from.
func (r *Repository) Dir() string { return r.dir }

// ResolveCommit turns a revision (sha, branch, tag, HEAD, origin/main...)
// into a commit.
func (r *Repository) ResolveCommit(rev string) (*object.Commit, error) {
	if rev == "" {
		return nil, errors.New("empty revision")
	}
	h, err := r.repo.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		// Branch names given as "origin/main" resolve through the remotes
		// reference namespace, try that before giving up.
		h2, err2 := r.repo.ResolveRevision(plumbing.Revision("refs/remotes/" + rev))
		if err2 != nil {
			return nil, fmt.Errorf("resolving revision %q: %w", rev, err)
		}
		h = h2
	}
	c, err := r.repo.CommitObject(*h)
	if err != nil {
		return nil, fmt.Errorf("reading commit %s: %w", h, err)
	}
	return c, nil
}

// MergeBase returns the best common ancestor of base and head. When head is
// a descendant of base, this is base itself.
func (r *Repository) MergeBase(base, head *object.Commit) (*object.Commit, error) {
	bases, err := base.MergeBase(head)
	if err != nil {
		return nil, fmt.Errorf("computing merge base: %w", err)
	}
	if len(bases) == 0 {
		return nil, fmt.Errorf("commits %s and %s have no common ancestor", base.Hash, head.Hash)
	}
	return bases[0], nil
}

// ChangedFiles lists every path touched between from and to: added,
// modified and deleted files, and both names of a rename.
func ChangedFiles(from, to *object.Commit) ([]string, error) {
	fromTree, err := from.Tree()
	if err != nil {
		return nil, fmt.Errorf("reading tree of %s: %w", from.Hash, err)
	}
	toTree, err := to.Tree()
	if err != nil {
		return nil, fmt.Errorf("reading tree of %s: %w", to.Hash, err)
	}
	changes, err := object.DiffTree(fromTree, toTree)
	if err != nil {
		return nil, fmt.Errorf("diffing trees: %w", err)
	}
	set := map[string]struct{}{}
	for _, ch := range changes {
		if ch.From.Name != "" {
			set[ch.From.Name] = struct{}{}
		}
		if ch.To.Name != "" {
			set[ch.To.Name] = struct{}{}
		}
	}
	files := make([]string, 0, len(set))
	for f := range set {
		files = append(files, f)
	}
	sort.Strings(files)
	return files, nil
}

// ReadFile returns the contents of path as it exists in the commit. Paths
// are repository-relative with forward slashes.
func ReadFile(c *object.Commit, path string) ([]byte, error) {
	path = strings.TrimPrefix(strings.TrimPrefix(path, "./"), "/")
	f, err := c.File(path)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return nil, fmt.Errorf("%w: %s @ %s", ErrNotFound, path, c.Hash)
		}
		return nil, fmt.Errorf("reading %s from %s: %w", path, c.Hash, err)
	}
	if f.Size > MaxFileSize {
		return nil, fmt.Errorf("%s in %s is too large (%d bytes, max %d)", path, c.Hash, f.Size, MaxFileSize)
	}
	rd, err := f.Reader()
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer rd.Close() //nolint:errcheck
	data, err := io.ReadAll(io.LimitReader(rd, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s in %s is too large (max %d bytes)", path, c.Hash, MaxFileSize)
	}
	return data, nil
}

// RemoteURL returns the fetch URL of the named remote, or "" if unknown.
func (r *Repository) RemoteURL(name string) string {
	rem, err := r.repo.Remote(name)
	if err != nil || rem == nil || len(rem.Config().URLs) == 0 {
		return ""
	}
	return rem.Config().URLs[0]
}
