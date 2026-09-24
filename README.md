# secure-cicd-platform

A reusable GitHub Actions security pipeline, and the evidence that its gates
actually stop bad code.

The demo application in `app/` is deliberately trivial. **The pipeline is the
engineering.** Any repository can consume it in five lines:

```yaml
jobs:
  security:
    uses: hasinosec/secure-cicd-platform/.github/workflows/security.yml@main
    with:
      image-name: my-service
```

---

## The problem

Most "DevSecOps pipeline" repositories run a scanner, print findings, and exit 0.
Nothing is ever blocked, so the pipeline is decoration. The three failures that
matter are:

1. **Findings that do not fail the build.** A report nobody reads is not a control.
2. **Mutable action references.** `uses: some/action@v4` is a tag. Whoever owns
   that repository can move the tag and execute arbitrary code inside CI, with
   whatever token permissions the workflow happens to hold.
3. **Over-broad `GITHUB_TOKEN` permissions.** The default token is writable. A
   compromised step in any job can push commits or publish releases.

This repository addresses all three and proves it with real scanner output.

## What the pipeline runs

| Stage | Tool | What it blocks |
|---|---|---|
| secrets | gitleaks | credentials in the tree **and in git history** |
| dockerfile lint | hadolint | Dockerfile anti-patterns |
| sast | semgrep | insecure code patterns (`p/security-audit`, `p/secrets`) |
| dependencies | pip-audit | known-vulnerable declared dependencies |
| iac | checkov | insecure infrastructure and Dockerfile configuration |
| container | trivy | CRITICAL/HIGH fixable CVEs in the built image |
| sbom | syft | SPDX SBOM published as a build artifact |
| policy gate | conftest / OPA | custom organisational rules (below) |
| security gate | — | one required check that fails if any stage failed |

Findings are uploaded as SARIF, so they appear in the GitHub Security tab rather
than only in a log nobody opens.

## Design decisions

**Every third-party action is pinned to a full 40-character commit SHA.**
Tags are mutable; commit SHAs are not. The policy gate enforces this on the
workflows in this repository, so the rule cannot quietly rot.

**`permissions: {}` at the top, widened per job.** Only `sast`, `iac` and
`container` receive `security-events: write`, and only because they upload SARIF.
No job can write to repository contents.

**CLIs are installed from their official release or install script, not from a
wrapper action.** Wrapper actions break on transitive deprecations and pin
badly — this cost real CI debugging time on an earlier project of mine, so the
pipeline installs `gitleaks`, `hadolint`, `trivy`, `syft` and `conftest`
directly at explicit versions.

**Report and gate are separate steps.** Trivy runs once to produce full SARIF for
the Security tab, then again with `--exit-code 1 --ignore-unfixed` to fail the
build. Developers see everything; only actionable, fixable findings block them.

## Custom policy (OPA / Rego)

`policy/` holds rules that no off-the-shelf scanner enforces, with unit tests.

**Dockerfile** — must declare a non-root `USER`; must not be `USER root`; base
images must be tagged (never `:latest`, never untagged); `ENV` keys that look
like credentials (`*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*API_KEY*`,
`*ACCESS_KEY*`) are rejected; `ADD` is rejected in favour of `COPY`; a missing
`HEALTHCHECK` warns.

**Workflows** — every `uses:` must be a full commit SHA or a local `./` path;
every workflow must declare a top-level `permissions` block.

```
$ conftest verify --policy policy
16 tests, 16 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped
```

## Evidence — the gates actually fire

`Dockerfile.weak` is a deliberately insecure build of the same application. The
`evidence` workflow runs the scanners against it and **fails if the weak build is
ever accepted**. Raw output is in `docs/evidence/`.

| Check | `Dockerfile.weak` | `Dockerfile` (hardened) |
|---|---|---|
| hadolint | **5 findings, exit 1** | **0 findings, exit 0** |
| gitleaks | **2 secrets detected** | clean |
| conftest policy | **4 failures, 1 warning** | **7 rules, 7 passed** |

```
$ conftest test --policy policy --namespace dockerfile Dockerfile.weak
WARN - Dockerfile has no HEALTHCHECK; orchestrators cannot tell a hung container from a healthy one
FAIL - Dockerfile must declare a non-root USER; containers must not run as root
FAIL - ENV 'AWS_ACCESS_KEY_ID' looks like a credential; use a secrets manager, not a build-time ENV
FAIL - ENV 'AWS_SECRET_ACCESS_KEY' looks like a credential; use a secrets manager, not a build-time ENV
FAIL - ENV 'DB_PASSWORD' looks like a credential; use a secrets manager, not a build-time ENV

7 tests, 2 passed, 1 warning, 4 failures, 0 exceptions
```

`Dockerfile.weak` contains no credential — only `__TEST_*__` placeholders.
`scripts/plant-test-secret.sh` fills them with random throwaway values at scan
time, so the scanners get a genuine pattern to detect while the repository stays
clean. Run it yourself: `./scripts/plant-test-secret.sh`.

## Real problems hit while building this

**GitHub push protection blocked my own test fixture — correctly.** The first
push was rejected: `GH013: Repository rule violations found`, flagging an
*Amazon AWS Access Key ID* and *Secret Access Key* in `Dockerfile.weak`. GitHub
offers a one-click "allow this secret" link. Taking it would have resolved the
push by teaching the repository to ignore exactly the finding class this
pipeline exists to catch. Instead the repository now stores only
`__TEST_*__` placeholders, and `scripts/plant-test-secret.sh` synthesises a
random throwaway credential pair **at scan time** into a gitignored file. The
gate still has a real pattern to detect; no credential-shaped literal is ever
committed.

**The fixture generator failed silently on its first run.** It used
`tr -dc ... </dev/urandom | head -c N`. `head` closes the pipe, `tr` dies on
`SIGPIPE`, and under `set -o pipefail` the script exited non-zero having written
nothing — while the scan that followed reported a clean tree and looked like a
pass. Rewritten using Bash's `RANDOM` with no pipes. Same lesson as below: a
green result is not evidence unless something asserts on the failure path.

**gitleaks ignored the first planted secret.** The initial weak Dockerfile used
`wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY` — AWS's own documentation example key,
which gitleaks allowlists by design. The scan reported zero findings and looked
like a working gate. Replacing it with a syntactically valid non-example key
produced the expected two detections. **A gate that reports nothing is
indistinguishable from a gate that is broken**, which is exactly why the
`evidence` workflow asserts on failure rather than trusting a green run.

**The hardened Dockerfile failed its own lint.** The first `HEALTHCHECK` used
shell form and tripped hadolint `DL3025`. Fixed by switching to JSON exec form
rather than suppressing the rule.

## What this does not cover

Stated plainly rather than implied:

- **No image signing or provenance.** Cosign signing, SLSA attestation and
  verify-before-deploy are the next repository (`software-supply-chain-security`),
  not this one.
- **No real deployment.** There is no cloud account behind this; the pipeline
  ends at a gated, scanned artifact. The manual-approval environment is declared
  but nothing is deployed through it.
- **Semgrep runs community rulesets only** (`p/security-audit`, `p/secrets`).
  No custom rules are written yet.
- **The demo application is not the point** and has had no threat modelling of
  its own beyond input truncation.

## Running it locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r app/requirements.txt pytest
.venv/bin/pytest -q

hadolint Dockerfile
gitleaks detect --source . --no-git --redact
conftest verify --policy policy
conftest test --policy policy --namespace dockerfile Dockerfile
conftest test --policy policy --namespace workflow .github/workflows/*.yml
```

## Licence

MIT — see [LICENSE](LICENSE).
