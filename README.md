# claim

Distributed authorization for path-based resources.

`claim` answers one question about a pull request: **is this person allowed to
change the files under this path?** It answers it even when the repository
receiving the change does not know, because the knowledge sits with whoever
*owns* the path. The repository decides *which policy* gates a path and *how
to find its owner*; the owner publishes *who is allowed*; claim brings the two
together and evaluates the policy with [AMPEL](https://github.com/policylabs/ampel).

```
 PR touches data/example.com/entry.yaml
          │
          ▼
 .claim.yaml (read from the merge target)
   rule: data/<host>/  →  policy: policies/signed-by-owner.json
                          owner:  https://<host>/.well-known/claim.yaml
          │
          ▼
 policy leaves `signers` open ──► fetch https://example.com/.well-known/claim.yaml
                                   context: { signers: [alice@example.com] }
          │
          ▼
 AMPEL evaluates the policy against the PR head commit
 (gitsign signature, git notes attestations)      ──►  PASS → allowed
```

## How it works

1. **Changed files.** claim walks the commits in `merge-base(base, head)..head`,
   lists the files each one touches (adds, edits, deletes, both names of a
   rename) and groups them by *owned path* according to the rules in
   `.claim.yaml`. A rule names a path prefix, the depth that forms one
   ownership unit (`data/` + 1 segment = `data/example.com/`) and the policy.
2. **Policy.** The rule's policy can live in the repository (read from the
   merge target) or be a remote AMPEL policy, set or group (`git+https://`
   locator or `https://` URL, ideally pinned to a commit).
3. **Owner.** claim finds the URL owning the path with one of two schemes:
   - `host`: the path segment is a host name; the owner document is at
     `https://<host>/.well-known/claim.yaml`.
   - `file`: a file inside the owned path (as of the merge target) holds the
     owner URL; claim extracts it with an RFC 6901 JSON pointer from JSON or
     YAML, or reads it from a text file. The URL is `https://host[/doc]` or
     a `git+https://host/org/repo[@ref][#doc]` locator.
   - `none`: no remote owner, the policy must be satisfiable locally.
4. **Context.** The owner document supplies values for the context entries
   the policy leaves open (no `value`, no `default`, no `expression`), and
   only for those the rule's `ownerContext` allows.
5. **Evaluation.** AMPEL evaluates the policy once per commit in the range
   that touched the owned path (subject: the commit's `gitCommit`/`sha1`
   digest) using the `gitsign` and `dnote` (git notes) collectors on the
   repository. A path passes only when every one of its commits passes, and
   the change is allowed only when **every** owned path passes. Clean merge
   commits change nothing on their own and are skipped; conflict resolutions
   count as changes.

Anything that prevents a verdict (no owner, unreachable or malformed owner
document, missing required context, unmatched files) **denies** the change
unless the configuration explicitly opts into allowing it.

## Usage

```
go install github.com/policylabs/claim/cmd/claim@latest

# In a checkout of the PR head commit, with the target branch fetched:
claim check --base origin/main --head "$PR_HEAD_SHA"
```

Exit codes: `0` allowed, `1` denied, `2` error. `--format json` prints the
full report including AMPEL results. See
[examples/github-actions.yaml](examples/github-actions.yaml) for a workflow.

> [!IMPORTANT]
> Point `--head` at the pull request **head commit**, not the synthetic merge
> commit GitHub checks out by default, and fetch with full history so the
> merge base and the commits in the range resolve.

## Configuration

`.claim.yaml` at the repository root, always read from the merge target:

```yaml
version: 1
unmatched: deny            # files no rule matches (deny|allow)
rules:
  - name: domains
    path: data/            # rule prefix
    depth: 1               # segments under path forming one owned unit (default 1)
    policy: policies/signed-by-owner.json
    owner:
      scheme: host         # none | host | file
      wellKnown: /.well-known/claim.yaml
    ownerContext: [signers]   # values the owner may supply (default: all open ones)
    onMissingOwner: deny      # deny|allow

  - name: vendors
    path: vendor/
    policy: git+https://github.com/carabiner-dev/policies@<sha>#path/to/policy.hjson
    owner:
      scheme: file
      file: metadata.json       # relative to the owned path
      format: json              # json|yaml|text, inferred from the extension
      pointer: /maintainers/claim
      document: claim.yaml      # default document when the URL names only a host/repo
      digests: [sha256:...]     # optional: pin the owner document (explicit rotation)
```

See [examples/registry](examples/registry) for a complete example and
[examples/owner/claim.yaml](examples/owner/claim.yaml) for the owner side.

## Owner document

```yaml
version: 1
context:
  signers: [alice@example.com]
paths:                        # per owned path, as the receiving repo names it
  data/example.com/:
    context: { signers: [alice@example.com] }
repositories:                 # per receiving repository (host/org/repo)
  github.com/some-org/registry:
    context: {...}
    paths: {...}
```

Most specific wins: `repositories.<repo>.paths.<path>` >
`repositories.<repo>` > `paths.<path>` > `context`.

## Design and security notes

[docs/design.md](docs/design.md) records the design, the review findings, the
security decisions, what this implementation covers and what is still open.

## License

Apache-2.0. Copyright by The Policy Labs Project Contributors.
