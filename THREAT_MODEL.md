# Threat model — the build pipeline

The asset being defended here is **the pipeline itself**, not the demo
application. A CI pipeline holds credentials, writes to the artifact registry and
runs third-party code on every push. It is a production system.

## Trust boundaries

```
developer push  ─►  GitHub Actions runner  ─►  artifact / registry
                          │
                          ├── third-party actions   (untrusted code)
                          ├── package registries     (untrusted content)
                          └── GITHUB_TOKEN           (credential)
```

Everything inside the runner is attacker-reachable the moment any one of those
three inputs is compromised.

## Threats and controls

| # | Threat | Realistic path | Control in this repo | Status |
|---|---|---|---|---|
| T1 | Malicious action version | Maintainer or attacker moves tag `v4` to a commit that reads secrets | All `uses:` pinned to full commit SHA; `policy/workflow.rego` fails the build if any reference is not a SHA | enforced |
| T2 | Token abuse from a compromised step | Any step inherits a writable `GITHUB_TOKEN` and pushes a commit or release | `permissions: {}` at workflow level; each job grants only what it needs; `security-events: write` only where SARIF is uploaded | enforced |
| T3 | Credentials committed to the repo | Developer hardcodes a key in a Dockerfile or source file | gitleaks over the working tree **and full history**; `policy/dockerfile.rego` rejects credential-shaped `ENV` keys | enforced, tested |
| T4 | Vulnerable dependency shipped | A known-CVE package is pulled into the image | pip-audit on declared requirements; Trivy on the built image, gated on fixable CRITICAL/HIGH | enforced |
| T5 | Container runs as root | Dockerfile omits `USER`, so a container escape lands as uid 0 | `policy/dockerfile.rego` requires a non-root `USER` and rejects `USER root` | enforced, tested |
| T6 | Findings reported but ignored | Scanner exits 0 and the report is never read | Every stage fails the build; a single required `security gate` job aggregates results | enforced |
| T7 | Broken gate that looks healthy | Scanner misconfigured, silently finds nothing, CI stays green | `evidence` workflow asserts the weak build is **rejected**; if a scanner stops detecting, CI fails | enforced |
| T8 | Unsigned or tampered image deployed | Registry compromise substitutes an image | **not covered here** — planned in `software-supply-chain-security` (cosign + verify before deploy) | gap |
| T9 | Dependency confusion / typosquat | Internal package name resolved from a public index | **not covered** — no private index in scope | gap |
| T10 | Compromised self-hosted runner | Persistent runner reused across jobs | **not applicable** — GitHub-hosted ephemeral runners only | n/a |

## Why T7 gets its own workflow

Every other control fails loudly. A misconfigured scanner fails **silently**: it
reports nothing, CI goes green, and confidence goes up while coverage goes to
zero. This happened during development — see the gitleaks allowlist note in the
README. The `evidence` workflow exists so that a scanner which stops detecting is
treated as a build failure, not as good news.

## Residual risk accepted

- Community semgrep rulesets only; no custom rules yet.
- Trivy gates on **fixable** findings (`--ignore-unfixed`). Unfixable CRITICALs
  are reported to the Security tab but do not block, because blocking on a
  finding with no available fix stops all delivery without reducing risk.
- The demo application itself is minimally reviewed; it is a test subject.
