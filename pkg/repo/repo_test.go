// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// commitFiles writes files into the worktree and commits them.
func commitFiles(t *testing.T, r *git.Repository, dir, msg string, files map[string]string, remove ...string) plumbing.Hash {
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
	for _, name := range remove {
		_, err = wt.Remove(name)
		require.NoError(t, err)
	}
	h, err := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	return h
}

func TestRepository(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	base := commitFiles(t, r, dir, "base", map[string]string{
		"README.md":      "hi",
		"data/a/one.txt": "1",
		"data/b/two.txt": "2",
	})
	// Branch off for the PR.
	wt, err := r.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("pr"), Create: true}))
	head := commitFiles(t, r, dir, "pr", map[string]string{
		"data/a/one.txt":   "changed",
		"data/c/three.txt": "3",
	}, "data/b/two.txt")
	// Move main forward so the merge base differs from the branch tip.
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.Master}))
	mainTip := commitFiles(t, r, dir, "main moves", map[string]string{"README.md": "moved"})

	repo, err := Open(dir)
	require.NoError(t, err)

	baseC, err := repo.ResolveCommit("master")
	require.NoError(t, err)
	require.Equal(t, mainTip, baseC.Hash)
	headC, err := repo.ResolveCommit(head.String())
	require.NoError(t, err)

	mb, err := repo.MergeBase(baseC, headC)
	require.NoError(t, err)
	require.Equal(t, base, mb.Hash)

	files, err := ChangedFiles(mb, headC)
	require.NoError(t, err)
	require.Equal(t, []string{"data/a/one.txt", "data/b/two.txt", "data/c/three.txt"}, files)

	data, err := ReadFile(baseC, "README.md")
	require.NoError(t, err)
	require.Equal(t, "moved", string(data))
	data, err = ReadFile(mb, "/data/a/one.txt")
	require.NoError(t, err)
	require.Equal(t, "1", string(data))
	_, err = ReadFile(baseC, "nope.txt")
	require.ErrorIs(t, err, ErrNotFound)

	_, err = repo.ResolveCommit("does-not-exist")
	require.Error(t, err)
	require.Empty(t, repo.RemoteURL("origin"))
}

func TestRange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	base := commitFiles(t, r, dir, "base", map[string]string{"README.md": "hi", "data/a.txt": "1"})
	wt, err := r.Worktree()
	require.NoError(t, err)
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("pr"), Create: true}))
	time.Sleep(1100 * time.Millisecond)
	c1 := commitFiles(t, r, dir, "c1", map[string]string{"data/a.txt": "2"})
	time.Sleep(1100 * time.Millisecond)
	c2 := commitFiles(t, r, dir, "c2", map[string]string{"data/b.txt": "3"})

	// main moves on.
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.Master}))
	time.Sleep(1100 * time.Millisecond)
	mainTip := commitFiles(t, r, dir, "main", map[string]string{"README.md": "moved"})

	// A clean merge of main into pr: the tree has both sides' changes and
	// nothing of its own.
	require.NoError(t, wt.Checkout(&git.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("pr")}))
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("moved"), 0o600))
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	merge, err := wt.Commit("merge main", &git.CommitOptions{
		Author:  &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()},
		Parents: []plumbing.Hash{c2, mainTip},
	})
	require.NoError(t, err)

	// An evil merge: resolves "conflicts" by changing a file neither side did.
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data/evil.txt"), []byte("x"), 0o600))
	_, err = wt.Add("data/evil.txt")
	require.NoError(t, err)
	evil, err := wt.Commit("evil merge", &git.CommitOptions{
		Author:  &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()},
		Parents: []plumbing.Hash{merge, mainTip},
	})
	require.NoError(t, err)

	repo, err := Open(dir)
	require.NoError(t, err)
	baseC, err := repo.ResolveCommit(mainTip.String())
	require.NoError(t, err)
	headC, err := repo.ResolveCommit(evil.String())
	require.NoError(t, err)
	mb, err := repo.MergeBase(baseC, headC)
	require.NoError(t, err)
	// main was merged into pr, so main's tip is the merge base now.
	require.Equal(t, mainTip, mb.Hash)

	commits, err := repo.CommitsInRange(mb, headC)
	require.NoError(t, err)
	hashes := make([]plumbing.Hash, 0, len(commits))
	for _, c := range commits {
		hashes = append(hashes, c.Hash)
	}
	require.Equal(t, []plumbing.Hash{c1, c2, merge, evil}, hashes)
	require.NotContains(t, hashes, base)

	changes := map[plumbing.Hash][]string{}
	for _, c := range commits {
		files, err := CommitChanges(c)
		require.NoError(t, err)
		changes[c.Hash] = files
	}
	require.Equal(t, []string{"data/a.txt"}, changes[c1])
	require.Equal(t, []string{"data/b.txt"}, changes[c2])
	require.Empty(t, changes[merge], "a clean merge changes nothing on its own")
	require.Equal(t, []string{"data/evil.txt"}, changes[evil])

	rootFiles, err := CommitChanges(mb)
	require.NoError(t, err)
	require.Equal(t, []string{"README.md"}, rootFiles)
	baseCommit, err := repo.ResolveCommit(base.String())
	require.NoError(t, err)
	rootFiles, err = CommitChanges(baseCommit)
	require.NoError(t, err)
	require.Equal(t, []string{"README.md", "data/a.txt"}, rootFiles)
}
