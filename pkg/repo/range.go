// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

// MaxRangeCommits bounds the number of commits claim evaluates in one run.
const MaxRangeCommits = 500

// CommitsInRange returns the commits reachable from head that are not
// reachable from base (git's base..head), oldest first. The merge base
// itself is excluded.
func (r *Repository) CommitsInRange(base, head *object.Commit) ([]*object.Commit, error) {
	// Everything reachable from base is excluded. Walking base fully can be
	// expensive on big histories, so walk head first and stop at anything
	// base reaches by checking ancestry lazily through a seen set built
	// from base limited to what head's walk needs.
	excluded := map[plumbing.Hash]bool{}
	baseIter := object.NewCommitPreorderIter(base, nil, nil)
	if err := baseIter.ForEach(func(c *object.Commit) error {
		excluded[c.Hash] = true
		return nil
	}); err != nil {
		return nil, fmt.Errorf("walking base history: %w", err)
	}

	commits := []*object.Commit{}
	headIter := object.NewCommitPreorderIter(head, excluded, nil)
	err := headIter.ForEach(func(c *object.Commit) error {
		if excluded[c.Hash] {
			return nil
		}
		commits = append(commits, c)
		if len(commits) > MaxRangeCommits {
			return fmt.Errorf("range has more than %d commits", MaxRangeCommits)
		}
		return nil
	})
	if err != nil && !errors.Is(err, storer.ErrStop) {
		return nil, fmt.Errorf("walking head history: %w", err)
	}
	// Oldest first so results read in the order the author made them.
	sort.SliceStable(commits, func(i, j int) bool {
		return commits[i].Committer.When.Before(commits[j].Committer.When)
	})
	return commits, nil
}

// CommitChanges lists the paths a commit touches on its own. For a commit
// with one parent that is the diff against it. A root commit touches every
// file it adds. For a merge commit only the paths that differ from every
// parent count: a clean merge of the base branch into the pull request
// branch changes nothing by itself, while conflict resolutions and evil
// merges show up as changes against all parents.
func CommitChanges(c *object.Commit) ([]string, error) {
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("reading tree of %s: %w", c.Hash, err)
	}
	if c.NumParents() == 0 {
		files := []string{}
		if err := tree.Files().ForEach(func(f *object.File) error {
			files = append(files, f.Name)
			return nil
		}); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("listing root commit %s: %w", c.Hash, err)
		}
		sort.Strings(files)
		return files, nil
	}

	var common map[string]struct{}
	for i := range c.NumParents() {
		parent, err := c.Parent(i)
		if err != nil {
			return nil, fmt.Errorf("reading parent %d of %s: %w", i, c.Hash, err)
		}
		changed, err := ChangedFiles(parent, c)
		if err != nil {
			return nil, err
		}
		set := map[string]struct{}{}
		for _, f := range changed {
			set[f] = struct{}{}
		}
		if common == nil {
			common = set
			continue
		}
		for f := range common {
			if _, ok := set[f]; !ok {
				delete(common, f)
			}
		}
	}
	files := make([]string, 0, len(common))
	for f := range common {
		files = append(files, f)
	}
	sort.Strings(files)
	return files, nil
}
