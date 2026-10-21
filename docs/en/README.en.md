# skill-publish-gate - Skill publish gate (code security + platform spec)

[![license: MIT-0](https://img.shields.io/badge/license-MIT--0-blue.svg)](LICENSE)

Before a skill ships you normally run two tools: **code security**
(credentials / injection / PII / malware patterns) and **platform spec**
(frontmatter hard validation / forbidden files / bundle size / declaration
consistency). This gate folds both into one local command, plus the
content-wording redlines for domestic platforms.

> **Rename**: originally `skillhub-gate` (history fully retained v1.0.0 ~ v1.4.0);
> renamed to `skill-publish-gate` in 2026-10. Code, CLI, exit codes and rule base are
> unchanged - only the skill identity no longer bakes in a single platform.
> Invoke the old name `@skill:skillhub-gate` as the new name.

> **v2.1.0 added the stitching layer**: SARIF 2.1.0 both directions
> (`--format sarif` / `--sarif-in`), unified fingerprint & baseline (`--baseline`),
> external config (`--config` / `--strict`), external scanner invocation
> (`--deep-scan` / `--offline`), stdlib-ast dangerous-call line numbers, agentic and
> MCP categories, `--platform ima`.

## Why it exists

- `skillhub publish --dry-run` only validates frontmatter; **forbidden file types only
  surface as a 400 at formal publish time**.
- Test artifacts mixed into the repo (`allure-results` / `.pytest_cache` / `data` /
  `.venv` / `node_modules`) bloat the package to tens of thousands of parts and the
  server stalls.
- Content review runs in parallel; wording redlines (network-circumvention word
  families, absolute claims, finance-sensitive phrasing) get rejected or delisted.
- Security side (credentials / prompt injection / malicious exec / PII) is usually
  unreviewed before publish, and by the time platform security scans reject it, it is
  already delisted.

The gate surfaces these "server-only failures" locally in one command.

## Install

```bash
# A: clone into the WorkBuddy skill directory
cd ~/.workbuddy/skills
git clone https://github.com/<you>/skill-publish-gate.git

# B: one-line install (with GitHub connector)
# Install this skill: https://github.com/<you>/skill-publish-gate

# C: import from GitHub into ClawHub (clawhub.ai -> import -> repo URL)
```

Dependency: PyYAML. The script auto-attempts `pip install pyyaml` if missing; if
unavailable it exits as a BLOCKER rather than a silent pass.

## Quick start

```bash
# single skill (default skillhub: LICENSE etc. are forbidden blockers)
python scripts/gate.py check --dir <skill>

# open-source copy pre-check (github: license/CI files exempt, other redlines still checked)
python scripts/gate.py check --dir <skill> --platform github

# ClawHub pre-check (any extension; wording word families downgraded to WARN;
# adds MIT-0 / requires-consistency checks)
python scripts/gate.py check --dir <skill> --platform clawhub

# ima pre-check (seven fields / zero _meta.json / ASCII quotes / ASCII filenames / <=5 triggers)
python scripts/gate.py check --dir <skill> --platform ima

# emit SARIF 2.1.0 (feed GitHub Code Scanning)
python scripts/gate.py check --dir <skill> --format sarif -o gate.sarif

# import an external deep scanner's SARIF (findings capped at medium, non-blocking)
python scripts/gate.py check --dir <skill> --sarif-in domsec.sarif

# run an external scanner directly (no shell; failure does not affect local verdict)
python scripts/gate.py check --dir <skill> \
    --deep-scan "python3 ~/tools/scanner.py --format sarif {dir}"

# baseline: suppress "confirmed false positives" (fingerprint stable across runs)
python scripts/gate.py check --dir <skill> --write-baseline ./baseline.json
python scripts/gate.py check --dir <skill> --baseline ./baseline.json

# external config: thresholds / forbidden-file append / custom rules (only stricter)
python scripts/gate.py check --dir <skill> --config ./gate.json

# machine-readable / write to file
python scripts/gate.py check --dir <skill> --format json
python scripts/gate.py check --dir <skill> --output gate-report.txt

# batch summary (all skills under a parent dir)
python scripts/gate.py dirs --dir ~/.workbuddy/skills

# feedback loop: write a newly-found gotcha back into rules/feedback.json
python scripts/gate.py check --dir <skill> \
    --learn '{"type":"blocker","pattern":"new-danger-word","reason":"platform rejected: ..."}'
```

Exit codes: `0`=PASS, `2`=NEEDS_FIX, `1`=BLOCKED. Drop into CI / pre-publish hook.

## Machine-verifiable invariants (injected by gen_en_docs.py, do not hand-edit)

- **GATE_VERSION / spec_version**: `3.4.0` (must equal `rules/skillhub-spec.json` `version`)
- **Exit-code contract**: `PASS`=`0` (No issues. Publishable.) | `NEEDS_FIX`=`2` (Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'.) | `BLOCKED`=`1` (At least one blocker. Must fix, else rejected or delisted.)
- **Rule IDs / CLI flags**: authoritative source is `rules/skillhub-spec.json` (`rules[].id`) + `scripts/ast_guard.py` (AST-*) + `scripts/gate.py` argparse; the English docs above mirror the Chinese docs and do not restate the full ID list. Drift is caught by `tests/test_en_docs.py` (recomputes the data source and asserts the invariant block version matches spec.json).
- **English disclaimer**: This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.

