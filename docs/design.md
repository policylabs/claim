# claim: design

claim is a policy tool for pull requests. It answers one question: *is this
person allowed to change files in this path?* The repository receiving the pull
request decides **which policies** gate each path, but it does not know, and
does not control, **who** is allowed. That knowledge belongs to the path owner,
and claim fetches it from them at evaluation time.

This document records the initial design, the gaps and security issues found
when reviewing it, and the decisions taken so far. Sections marked **Open**
still need a decision.

## 1. Overview

```
  PR opened / updated
         │
         ▼
  claim computes base..head and the paths each commit touched
         │
         ▼
  for every owned path touched:
      read .claim config and policies FROM THE BASE BRANCH
      resolve the path owner reference  ──►  Resolver (https, git, navajo, …)
      fetch + verify the owner document ◄──  (signed; supplies context values)
      for every commit touching the path:
          collect evidence (commit signature, git notes attestations)
          run the AMPEL policy with the commit as subject
          store the result keyed by (commit, path, policy digest, owner doc digest)
         │
         ▼
  PR status on the head SHA = all (commit, path) pairs have a passing result
  claim emits an AMPEL results attestation; branch protection requires the check
```

claim never merges anything. It produces a check status and a signed results
attestation. Merging stays with the forge's branch protection.

## 2. Components

### 2.1 Repository configuration (`.claim`)

The receiving repository keeps a `.claim` file (format: YAML, exact name
**Open**) at the repository root that maps paths to policies and to an owner
resolution strategy.

Required semantics:

- **Matching.** Longest-prefix match on directory paths. Globs are a possible
  later addition; prefix matching is enough for the first version and is
  easier to reason about.
- **Multiple owners in one PR.** If a PR touches paths with different owners,
  every owner's policy must pass. There is no "majority" or "any" mode.
- **Unowned paths.** Files under no configured path are outside claim's scope.
  Whether that means "pass" or "fail" is a per-repository setting; the default
  is **fail** (see §4.1).
- **Read from the base branch, always.** `.claim`, the policies it references,
  and any file used for owner extraction (§2.3.2) are read from the base
  branch, never from the PR head. See §4.3.

### 2.2 Unit of evaluation: commits in a range, not the head commit

The original sketch evaluated "the last commit in the PR". That is the wrong
unit: a PR is a range, earlier commits may carry other people's changes, and
only the head commit's signature would ever be checked. A squash merge makes
it worse: the squashed commit is signed by the forge, not the author, so the
author's signature disappears exactly when it matters.

**Decision.** AMPEL stays ignorant of pull requests. It evaluates a subject.
claim owns the range logic:

1. claim computes `base..head`.
2. For each commit, claim lists the paths it touched using
   `git diff-tree --no-commit-id --name-status -r <sha>` (this includes renames
   and deletions, which `--stat` truncates).
3. For each owned path, the set of commits that touched it is what needs
   authorization. claim runs the path's policy once per commit with that commit
   as the subject, collecting evidence attached to that commit.
4. A path passes only when every one of its commits passes. The head commit is
   just one more commit in the loop, so "evaluate HEAD" and "evaluate the
   range" collapse into one mechanism.

Merge commits from the base branch inside the range are skipped when they are
true merges with no path changes, and treated as ordinary commits when they
carry conflict resolutions.

**Alternative kept for later.** If per-commit runs are too slow, claim can emit
one attestation per PR describing each commit, its signer, and the files it
touched, and a single policy evaluates that attestation. It is cleaner for
owners to write policies against, but claim's attestation becomes trusted
input: claim would have to sign it and the policy would have to pin claim's
identity. Start with the per-commit loop.

### 2.3 Owner resolution

An **owner reference** is a scheme-prefixed URI. The scheme selects a
**resolver**. The verification and context-merge logic (§2.4) lives in claim
and never varies per scheme.

Resolver contract:

- Input: an owner reference.
- Output: the owner document bytes, a **trust statement** (who signed it, or
  which transport authenticated it), and a **digest** used in the results cache
  key (§2.6).
- Every resolver is subject to the same security floor (§4).

Planned resolvers:

| scheme        | status  | notes                                                     |
|---------------|---------|-----------------------------------------------------------|
| `https://`    | first   | fixed well-known location, see below                      |
| `navajo://`   | planned | the user intends to support it; reference format **Open** |
| `git+https://`| later   | `git+https://host/org/repo@ref#path`                      |

**Open: navajo.** The project intends to support "navajo" as a resolution
system. It is not yet known what an owner reference looks like in it or what
trust it provides. If it delivers signed owner documents with a verifiable
identity, it should become the preferred resolver over plain https (§4.2).

#### 2.3.1 Strategy 1: derive the owner from the path

A path segment names a host. For `./data/example.com`, the owner reference is
`https://example.com/.well-known/claim.yaml` (exact well-known path **Open**,
candidates: `/.well-known/claim.yaml` or `/.well-known/claim/<path>.yaml`).

The segment is **untrusted input** and must be validated before it becomes a
URL (§4.4, §4.5). Which segment is the host (first under the owned prefix) is
part of the `.claim` entry.

#### 2.3.2 Strategy 2: extract the owner from a file in the path

The `.claim` entry names a file relative to the owned path and a pointer into
it, for example `owner.json` + JSON Pointer `/document/struct/field`.

**Decision.** Restrict to JSON and YAML, addressed with a JSON Pointer
(RFC 6901) or, if needed, a small CEL expression. Supporting arbitrary file
types is an open-ended parser surface with little upside. The file is read
from the base branch (§4.3).

### 2.4 Owner document and context values

AMPEL policies declare the context values they need under `context`, with a
`value`, a `default`, and a `required` flag. Values burned into the policy are
immutable; required values that are missing make the evaluation error before
any tenet runs. Names may not clash when lowercased, and there is no type
coercion.

The owner document supplies the missing context values. Rules:

- **Allowlist.** The `.claim` entry (or the policy itself) lists which context
  keys the owner document may supply. claim rejects unknown keys and keys that
  clash with existing ones after lowercasing.
- **Types are the policy's problem to state.** Since AMPEL does no coercion, a
  YAML string where the policy expects a list fails late and confusingly. The
  owner document format should carry the expected type, or claim should
  validate the shape against a per-key declaration before calling AMPEL.
- **Owner documents are attestations, not bare files.** See §4.2.

Example: a policy checks a commit signature against an identity list but leaves
`allowed_identities` as a required context value with no default. The owner
document for the path supplies that list; claim injects it and runs the policy.

### 2.5 Evidence collection

By default claim looks for evidence on each commit:

- the commit signature (gitsign / SSH / GPG), which yields the **signer
  identity**; and
- attestations stored in **git notes** attached to the commit.

**Finding.** The existing `policylabs/collector` git backend clones a ref and
reads attestation files from the tree through the filesystem collector. It does
not read commit signatures or git notes. claim needs a new collector (or an
extension of the git one) that:

- fetches `refs/notes/*` explicitly, because PR refs do not carry them;
- exposes the commit signature as evidence the policy can inspect; and
- treats notes as **transport only**: trust comes from the attestation
  signature inside the note, never from the note's presence (§4.6).

### 2.6 Results store and PR status

The PR status should be a lookup, not a re-evaluation.

- **One result per `(commit SHA, path, policy digest, owner document digest)`.**
  A commit's touched paths and signature never change, so a result is reusable
  across pushes that keep that commit. Only new commits in the range get
  evaluated.
- **The status on the head SHA** is: for the current `base..head`, every
  `(commit, path)` pair has a passing result. A force push changes the range,
  so stale results fall away naturally.
- **The store can be AMPEL results attestations.** AMPEL signs its evaluation
  results, so keeping them in git notes or an attestation store gives a cache
  that is also evidence. Trust comes from verifying claim's signature on the
  result, not from where it was stored.
- **Invalidation is in the key.** A policy or owner-document change changes a
  digest and old results stop matching. Owner documents should additionally
  carry a **time-to-live**, so that an owner revoking someone takes effect even
  when nothing else in the range changed.

### 2.7 Identity: who is "this person"

The forge's PR author is forgeable from the commit's point of view. The
**subject identity is the verified commit signer**, as produced by the
signature collector. **Open:** how co-authored commits are handled (require all
signers to be allowed, or only the committer).

## 3. Review: gaps in the original design

| # | gap                                       | resolution                                   |
|---|-------------------------------------------|----------------------------------------------|
| 1 | path to policy mapping undefined          | §2.1 longest prefix, all owners must pass    |
| 2 | "last commit" is the wrong unit           | §2.2 per-commit loop over base..head         |
| 3 | config in the PR is attacker controlled   | §4.3 read everything from the base branch    |
| 4 | owner URL schema unspecified              | §2.3 scheme-selected resolvers; https first  |
| 5 | data extraction unbounded                 | §2.3.2 JSON/YAML + JSON Pointer only         |
| 6 | identity undefined                        | §2.7 verified commit signer                  |
| 7 | remote may fill any context key           | §2.4 allowlist + lowercase clash rejection   |
| 8 | output undefined                          | §1 check status + results attestation        |
| 9 | collector cannot read signatures or notes | §2.5 new collector                           |

## 4. Review: security issues to fix before code

### 4.1 Fail-open on missing owner data

The original text says that if an owner fails to supply owner data "the PR may
be fulfilled". That means a 404, an expired domain, or an outage authorizes
merges. **Default to fail-closed.** A repository may opt in to fail-open per
path, explicitly.

### 4.2 Trust in the owner document is only TLS

With a bare https fetch, whoever controls the web server or the DNS record
controls merge rights. **Serve the owner document as a signed attestation** and
pin the expected signer identity or key in `.claim`. At minimum, pin the
document by digest with an explicit rotation step. Changing a path's owner
reference in `.claim` should itself require authorization from the current
owner.

### 4.3 Configuration read from the PR head

`.claim`, the referenced policies, and any extraction file are all files a PR
can change. Reading them from the PR head lets the author grant themselves
access. Read them from the **base branch** only.

### 4.4 SSRF through derived URLs

claim runs in CI with network access. A directory named like an internal host
or `169.254.169.254` becomes a fetch target under strategy 1. Validate the
segment as a strict hostname, convert IDNA to ASCII, reject IP literals, ports,
userinfo, and private or link-local ranges (after DNS resolution too), and do
not follow redirects to any of them. Apply timeouts, size caps, and
content-type checks on the response.

### 4.5 Path traversal in derivation and extraction

Segments such as `..`, encoded slashes, and homoglyph domains must be rejected
before they become part of a URL or a filesystem read. Extraction files are
resolved relative to the owned path and may not escape it.

### 4.6 Git notes are mutable and unsigned

Anyone with push access can attach or rewrite notes. Notes are a transport.
Trust comes from the attestation signature inside the note. Fetch notes refs
explicitly.

### 4.7 Time of check versus time of merge

Bind the evaluation to the exact head SHA that gets merged. A push after a
passing check must not ride the earlier result. The results-store design in
§2.6 handles this: the status is computed for the current range only.

## 5. Open questions

1. **navajo.** What is it, what does an owner reference look like, and what
   trust does it provide? (§2.3)
2. **Well-known path** for the https resolver. (§2.3.1)
3. **Config file name and schema** for `.claim`. (§2.1)
4. **Owner document format**: how it declares context values, their types, and
   its TTL. (§2.4)
5. **Co-authored commits.** (§2.7)
6. **Fail-open opt-in**: per path, per repository, or not at all. (§4.1)

## 6. Next steps

1. Decide the open questions above, starting with navajo and the `.claim`
   schema.
2. Scaffold the Go module: `.claim` loader (base-branch only), resolver
   interface with the https resolver and the validation from §4.4 and §4.5,
   the per-commit evaluation loop, and the AMPEL wrapper that injects
   allowlisted context values.
3. Write the commit-signature and git-notes collector.
4. Add the results store and the PR status computation.

## 7. Implementation status

This section tracks how the code in this repository maps to the design above.
It is updated with the code.

### 7.1 Decisions taken by the implementation

These were marked **Open** above; the implementation picks a default so the
tool can run. Each is a proposal, revisit as needed.

| open item | decision in code |
|---|---|
| config file name and schema (§2.1, Q3) | `.claim.yaml` at the repository root, `version: 1`. Ordered `rules`, each with `path` (prefix), `depth` (segments forming one owned unit), `policy`, `owner`, `ownerContext`, `onMissingOwner`, extra `collectors`. Repository-wide `unmatched: deny\|allow`. See `pkg/config`. |
| matching (§2.1) | First matching rule in order (rules are an ordered list, so "longest prefix" is whatever order the repository writes). Depth makes the owned unit explicit instead of inferring it. |
| well-known path (§2.3.1, Q2) | `https://<host>/.well-known/claim.yaml`, overridable per rule with `owner.wellKnown`. |
| owner reference schemes (§2.3) | `host` (derive from the segment) and `file` (JSON/YAML + RFC 6901 pointer, or a text file with the bare URL) resolve to `https://` or `git+https://` owner URLs. `git+https://` is implemented through the SPDX VCS locator library already used by AMPEL. `none` marks paths with no remote owner. No `navajo` resolver yet (Q1). |
| owner document format (§2.4, Q4) | YAML/JSON, `version: 1`, a `context` map, plus `paths` and `repositories[...].paths` scopes so one document can serve several repositories and paths. Most specific scope wins. No TTL yet (there is no results store to expire). No type declarations: AMPEL converts the simple types (string/int/bool) when the policy types the value. |
| fail-open opt-in (§4.1, Q6) | Per rule, `onMissingOwner: allow`; per repository, `unmatched: allow`. Both default to deny. With `allow`, claim still evaluates the policy when the local context suffices and only skips evaluation when it cannot (`ALLOWED_UNCHECKED`). |
| output (§1) | A report (text or `--format json`) with one entry per owned path and per commit, including the AMPEL results. Exit codes 0 allowed, 1 denied, 2 error. No results attestation yet (§7.3). |

### 7.2 Design points implemented

- **Per-commit evaluation over the range (§2.2).** `pkg/repo` walks
  `merge-base..head`, lists the paths each commit touches on its own (diff
  against the parent; for merges, the intersection of the diffs against every
  parent, so clean merges change nothing and conflict resolutions count), and
  `pkg/claim` evaluates each owned path once per touching commit. A path passes
  only when every commit passes. Policies and owner documents are loaded once
  per path per run.
- **Everything trusted is read from the base commit (§4.3).**
  `.claim.yaml`, repository-local policies and owner pointer files come from
  `--base`. `TestCheckRulesComeFromBase` rewrites all three in a PR and
  checks none of it counts.
- **Fail closed (§4.1).** No owner, unreachable or malformed document, digest
  mismatch, invalid host, missing required context, unmatched files, shallow
  files and policy errors all deny unless the configuration opts out.
- **Context allowlist and clash rejection (§2.4).** The owner may only fill
  context values the policy leaves open (no `value`, `default` or
  `expression`); `ownerContext` narrows that list or lets the owner override
  a default on purpose. Names that collide once lowercased, or that differ
  only in case from an allowed name, make the document invalid. Keys the
  policy does not take are dropped with a warning (not rejected) so one owner
  document can serve policies with different context sets. Local providers
  always win over the owner.
- **SSRF and traversal defenses (§4.4, §4.5).** `https`/`git+https` only;
  strict RFC 1123 host validation after IDNA to ASCII; IP literals, ports,
  userinfo, `..`, local names refused; the dialer resolves the host and
  refuses non-public addresses at connection time; no redirects; no proxy
  from the environment; 1 MiB and 20 s caps; HTML-ish content types refused.
  Pointer files are resolved relative to the owned path and may not escape
  it. `--allow-private-owners` disables the network guard for local testing.
- **Owner document pinning (§4.2, minimum).** `owner.digests` pins the
  document to a sha256; a document matching none is treated as missing.
- **Evidence collectors (§2.5).** The finding that `policylabs/collector`
  could not read signatures or notes is out of date: v0.4.0 ships a
  `gitsign` collector (synthesizes a `https://gitsign.sigstore.dev/predicate/git/v0.1`
  attestation carrying the verified signer, with Rekor lookup) and `note`/`dnote`
  collectors that fetch `refs/notes/commits` explicitly. claim loads
  `gitsign:<repo>` and `dnote:<repo>` by default; notes remain transport only,
  trust comes from the attestation signature AMPEL verifies (§4.6).
- **Identity is the verified signer (§2.7).** The example policy reads
  `verification.signers` and checks the sigstore identity and issuer against
  the owner-supplied `signers` list.
- **Head SHA binding (§4.7).** The report records base, merge base, head and
  every commit evaluated.

### 7.3 Not yet implemented

- **Results store and PR status computation (§2.6).** Every run evaluates the
  whole range. Keying results by `(commit, path, policy digest, owner document
  digest)` and signing them as AMPEL results attestations is the next step; it
  also brings the owner-document TTL.
- **Signed owner documents (§4.2).** Trust rests on TLS (or the git host) plus
  optional digest pinning. The document `version` field leaves room for a
  signed envelope.
- **navajo resolver (Q1).** The resolver boundary is `owner.Resolve` +
  `owner.Fetcher.Fetch`; a new scheme plugs in there.
- **Type validation of owner values (§2.4).** Beyond AMPEL's simple-type
  conversion, nothing checks that a list is a list before evaluation.
- **Co-authored commits (Q5).** Still open; the gitsign collector reports the
  commit signer only.
- **Changing a path's owner reference requires the current owner's
  approval (§4.2).** Not enforced; it is an ordinary change to a base-branch
  file today.
