#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成英文版文档（docs/en/*.en.md），从中文版 + 规则库注入。

为什么是「生成器 + 共享源」而不是手写两份独立 md：
  两份独立 md 必然漂移——规则 ID 改名、CLI 加参数、退出码调整时只改了中文那份，
  英文版就成了过期翻译。本生成器把「可机验的不变量」从唯一数据源
  （rules/skillhub-spec.json 与 scripts/gate.py 的 argparse）直接注入英文版，
  纯翻译文本才手写。任何一边漂移都会被 tests/test_en_docs.py 抓住。

不变量注入规则（与中文版同源）：
  - 规则 ID 集合：从 spec.json 的 rules[].id + ast_guard.py 的 AST-* 字面量抽取
  - CLI 参数：从 gate.py 的 argparse 抽取（与中文版 cli-reference 同源）
  - 退出码契约：0/2/1，与 verdict 一一对应
  - 版本号：从 spec.json 的 version 字段注入（中英文版必须一致）

产物：docs/en/SKILL.en.md、README.en.md、rule-catalog.en.md、cli-reference.en.md
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")


def _spec_rule_ids() -> list:
    p = os.path.join(ROOT, "rules", "skillhub-spec.json")
    with open(p, encoding="utf-8") as f:
        d = json.load(f)
    return [r["id"] for r in d["rules"]]


def _ast_rule_ids() -> list:
    p = os.path.join(ROOT, "scripts", "ast_guard.py")
    with open(p, encoding="utf-8") as f:
        src = f.read()
    return sorted(set(re.findall(r'"(AST-[A-Z0-9][A-Z0-9-]*)"', src)))


def _cli_flags() -> list:
    p = os.path.join(ROOT, "scripts", "gate.py")
    with open(p, encoding="utf-8") as f:
        src = f.read()
    return sorted(set(re.findall(r'--([a-z][a-z0-9-]*[a-z0-9])', src)))


def _spec_version() -> str:
    p = os.path.join(ROOT, "rules", "skillhub-spec.json")
    with open(p, encoding="utf-8") as f:
        return json.load(f)["version"]


# 退出码契约（中英共享，gate.py verdict() 的固定行为）
EXIT_CODE_CONTRACT = [
    ("PASS", "0", "No issues. Publishable."),
    ("NEEDS_FIX", "2", "Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'."),
    ("BLOCKED", "1", "At least one blocker. Must fix, else rejected or delisted."),
]

# 免责声明（中英共享，gate.py GATE_DISCLAIMER 的固定文案）
EN_DISCLAIMER = ("This gate performs a local spec pre-check and static security scan only. "
                 "It does NOT constitute a publishing guarantee for any platform. The final "
                 "publishability is decided by each platform's own review; responsibility lies "
                 "with the skill author.")


def render_contract_block() -> str:
    """渲染「机器可验不变量」代码块，注入每个 .en.md 末尾。

    只保留真正「跨语言共享且不可变」的锚点（版本号 + 退出码契约）：
      - 规则 ID / CLI flags **不逐条内嵌**——把它们逐条写进每个 .en.md 会与正文表格
        的引用叠加，导致英文版「引用了中文版没写的 ID」（测试 7 实测复现过）。
      - 防漂移靠 tests/test_en_docs.py 独立重算数据源并断言，不在文档里重复维护。
    """
    ver = _spec_version()
    lines = [
        "## Machine-verifiable invariants (injected by gen_en_docs.py, do not hand-edit)",
        "",
        f"- **GATE_VERSION / spec_version**: `{ver}` (must equal `rules/skillhub-spec.json` `version`)",
        "- **Exit-code contract**: " + " | ".join(
            f"`{v}`=`{c}` ({t})" for v, c, t in EXIT_CODE_CONTRACT),
        "- **Rule IDs / CLI flags**: authoritative source is `rules/skillhub-spec.json` "
        "(`rules[].id`) + `scripts/ast_guard.py` (AST-*) + `scripts/gate.py` argparse; "
        "the English docs above mirror the Chinese docs and do not restate the full ID list. "
        "Drift is caught by `tests/test_en_docs.py` (recomputes the data source and asserts "
        "the invariant block version matches spec.json).",
        f"- **English disclaimer**: {EN_DISCLAIMER}",
        "",
    ]
    return "\n".join(lines)


# ── 各 .en.md 的纯翻译文本（手写；不变量在末尾由 render_contract_block 追加）──

SKILL_EN = """# Skill Publish Gate (`skill-publish-gate`)

> **Layered layout (progressive disclosure)**: this file only carries what every round
> needs - section 0 hard constraints and section 1 single-run flow. Everything else lives
> in `references/` and is read on demand, not pre-loaded.

---

## Section 0. Hard constraints - re-read each round, even after context compression

### 0.1 Capability boundary

- This gate only judges "can this skill be published". It does **not** re-implement
  general code auditing. The deep layer is stitched in via `--sarif-in` / `--deep-scan`,
  but the deep layer **never** decides publishability on its own.
- The verdict is a **local pre-check, not a platform review guarantee**. Always relay
  this caveat to the user; never phrase it as "the review will pass".

### 0.2 Exit-code contract - the verdict is authoritative

| verdict | exit | meaning |
|---------|------|---------|
"""


def _skill_en() -> str:
    rows = "\n".join(f"| `{v}` | `{c}` | {t} |" for v, c, t in EXIT_CODE_CONTRACT)
    return (SKILL_EN
            + rows + """

- With `--format json`, stdout carries only JSON; errors go to stderr, so it pipes cleanly.
- The exit code is for CI. **The user-facing verdict is the `verdict` field**, not the exit code.

### 0.3 Execution model

- Default: scan only the git-tracked set (equivalent to "what would be published").
  Auto full-scan if the target is not a git repo; force full-scan with `--all-files`.
- Default zero-network, zero-required-secret. Only `--deep-scan` executes an external
  command - do not use it unless the user explicitly supplied it; if used, state in the
  report that deep results come from an external scanner.

### 0.4 Three iron laws (all from real incidents)

1. **"Feature legal" != "documentation compliant"**: a fully legal feature still trips a
   violation for one phrase like "improved reachability of overseas sources". Fix the
   wording; do not try to rationalize the feature.
2. **`--proxy` positioning**: frame it as "enterprise intranet requires outbound traffic
   through a unified proxy", and explicitly state "provides and supports no capability to
   circumvent network-management measures".
3. **Degrade, do not work around**: when an external source is unreachable, the defined
   behavior is to degrade to domestic sources + offline snapshot + honest labeling -
   not "configure a proxy to restore access".

---

## Section 1. Single-run flow - 5 steps, closed within one round

Each step states input / action / output / fallback. **Do not re-read this file across
rounds**; the 5 steps close the task.

### Step 1 - Pin the target and the platform

- **Input**: the skill directory the user points to (ask, or use `dirs` to list
  candidates) and the target platform.
- **Action**: fix `--dir` and `--platform` (default `skillhub`). If the platform is
  uncertain, ask - a wrong platform makes the verdict meaningless. `github` is for the
  open-source copy; `clawhub` / `ima` each have their own relaxed/stricter rules.
- **Output**: one concrete command, e.g.
  `python scripts/gate.py check --dir <dir> --platform <platform>`.
- **Fallback**: `--dir` missing or not a directory -> exit 2 (no silent review of something else).

### Step 2 - Run the gate

- **Input**: the Step 1 command. Add `--format json` for machine-readable; `dirs` for batch.
- **Action**: execute. Add `--show-info` to surface default-muted INFO hits.
- **Output**: verdict + exit code; with `--format json`, also `issues[]`.
- **Fallback**: missing PyYAML triggers an auto-install attempt; if that fails it exits
  as a BLOCKER, **never** a silent pass.

### Step 3 - Locate and explain each hit

- **Input**: the issues from Step 2.
- **Action**: open the real code/doc at `file:line` and verify. **Do not apply the
  `recommendation` verbatim** - confirm it still holds in context.
- **Output**: one sentence per hit: "what it is + why it matters here".
- **Fallback**: when unsure, label it "suspected, needs human confirmation".

### Step 4 - Fix or advise

- **Input**: the confirmed-true hits.
- **Action**: fix what is directly fixable (wording issues: fix the doc, not the feature).
  After fixing, **re-run Step 2** - this gate dogfoods itself.
- **Output**: change list + new verdict.
- **Fallback**: if a hit is a false positive, say **why not to fix it**, and offer a
  `--learn` whitelist suggestion the user must confirm.

### Step 5 - Deliver the verdict

- **Input**: final verdict + fixes.
- **Action**: three-part answer "verdict + blockers + warnings" with the disclaimer.
- **Output**: the user can decide "publish" or "fix first".

---

## Section 6. Disclaimer

""" + EN_DISCLAIMER + "\n"
          + render_contract_block() + "\n")


README_EN = """# skill-publish-gate - Skill publish gate (code security + platform spec)

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
python scripts/gate.py check --dir <skill> \\
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
python scripts/gate.py check --dir <skill> \\
    --learn '{"type":"blocker","pattern":"new-danger-word","reason":"platform rejected: ..."}'
```

Exit codes: `0`=PASS, `2`=NEEDS_FIX, `1`=BLOCKED. Drop into CI / pre-publish hook.

"""


def _readme_en() -> str:
    return README_EN + render_contract_block() + "\n"


RULE_CATALOG_EN = """# Rule catalog (read on demand, do not pre-load)

> SKILL.md section 1 gives "how to run"; this gives "what each class means".
> For exact pattern / severity / platform downgrade of a rule, consult
> `rules/skillhub-spec.json` (single source of truth; gate.py holds no word lists).

## 1. Code security (SECURITY / PRIVACY)

All four platforms (skillhub / github / clawhub / ima) treat these as **BLOCKERs**;
they do not downgrade by platform.

| Rule | What it checks | Default tier |
|------|---------------|--------------|
| SEC-CRED-001 | Suspected token/key (GitHub PAT, AWS AKIA, GitLab PAT, Slack, AIza, ...); hits are redacted to `[REDACTED_SECRET]` | critical / redline |
| SEC-MALWARE-001 | Malicious exec patterns (base64-then-eval/exec, download-and-exec, reverse shell, `rm -rf /`, ...) | critical |
| SEC-PROMPT-001 | Prompt-injection markers ("ignore previous instructions", jailbreak, DAN, ...) | critical |
| SEC-PERSIST-001 | Instructing the host to permanently tamper persistent files (SOUL.md / MEMORY.md / IDENTITY.md / USER.md) | critical |
| OSS-COPYLEFT-001 | Copyleft license family - violation triggers derivative-work open-source duty | critical / redline |
| OSS-STRIP-001 | Stripping third-party copyright / license statements | critical / redline |
| META-MISMATCH-001 | Script contains file-write / subprocess / network but frontmatter lacks a `requires` declaration (ClawHub) | medium |
| AST-*-001 | stdlib-ast precise-line dangerous calls (see invariant block at the end for the full list) | high |
| PRIV-PATH-001 | Absolute-path leak (including local username) | medium |
| PRIV-NAME-001 | Real name / username (public pen name already excluded) | medium |
| PRIV-MEAS-001 | Real measurement values (phrases that expose repo size, e.g. "52 files repo-wide") | medium |
| PRIV-PII-001 | PII: national ID / phone / bank card | critical |

> AST rules are implemented by `scripts/ast_guard.py` (not in the rule base) using the
> stdlib `ast`, matching on dotted call paths - so `json.loads` is not flagged while
> `os.system` is. `# noqa` / `# nosec` / `# gate: allow` comments exempt a single hit,
> for both single-line and multi-line calls. Parse failures are recorded as notes only.

## 2. Platform spec (SPEC)

| Check | Consequence |
|-------|-----------|
| FRONTMATTER parsed with real `yaml.safe_load`; catches half-width "colon + space" silent failures | BLOCKED |
| Required fields: `slug` (kebab-case 2-128) / `version` (SemVer) / `displayName` | BLOCKED |
| Recommended fields: `name` / `description` / `summary` / `tags` | NEEDS_FIX |
| Forbidden files: `.gitignore` / `.nojekyll` / `LICENSE` / `__pycache__` / `*.pyc` / `.github` / `.clawhubignore` | BLOCKED (github exempts the first four) |
| Artifact hygiene: `.github_token` / `.workbuddy` / `.env` / `.venv` / `node_modules` must not enter the package | BLOCKED |
| Bundle: file count / total size over threshold | BLOCKED / NEEDS_FIX |
| Version consistency: `version` uniform across SKILL.md / config.json / metadata.json / CHANGELOG.md | NEEDS_FIX |
| Network declaration: `network: none` but a script makes real network calls | NEEDS_FIX |
| Dependency pinning: `requirements.txt` not pinned to `==version` | NEEDS_FIX |
| INFO-PROXY-001 | outbound-proxy mention (`--proxy` / `HTTPS_PROXY`) | info (default-muted, needs human confirmation) |

## 3. Content compliance (CONTENT)

Mirrors platform review redlines. Word lists come from the 2026-09-22 ai-weekly
wording delisting incident.

| Rule | What it checks | Consequence |
|------|---------------|-------------|
| RED-NET-001~003 | Network-circumvention word families (Chinese words + proxy-tool siblings + VPN/subscription) | BLOCKED (clawhub downgrades to WARN) |
| RED-NET-004 | Circumvention-framed feature narrative ("restore access / lift the restriction") | BLOCKED / NEEDS_FIX |
| RED-NET-005 | Extended word list & narrative regexes frozen from the delisting incident | BLOCKED (clawhub downgrades to WARN) |
| RED-AD-001 | Advertising-absolute claims (best / first / only / top-tier, ...) | NEEDS_FIX |
| RED-FIN-001 | Finance-sensitive phrasing (stock tips / guaranteed returns / insider info, ...) | NEEDS_FIX |

**Meta-context exemption**: a hit word inside a "negation / definition / list /
explanation" context is treated as self-description and not flagged - so compliance and
security skills that merely enumerate rule words are not flagged by themselves.

## 4. Agentic / MCP categories (v2.1.0+)

General code scanners do not read SKILL.md and cannot catch "instructional" risk -
these two classes can only be guarded by a publish gate.

| Rule | What it checks | Consequence |
|------|---------------|-------------|
| AGENT-MEMORY-001 | Memory poisoning: requires cross-session permanent recall of user identity/preferences | BLOCKED (clawhub downgrades to high) |
| AGENT-LEAK-001 | System-prompt leakage: requires outputting/echoing the system prompt or internal rules | BLOCKED (clawhub downgrades to WARN) |
| AGENT-AUTONOMY-001 | Excess agent authority: executes irreversible actions (delete/pay/publish/transfer) without user confirmation | BLOCKED (clawhub downgrades to WARN) |
| AGENT-REFUSAL-001 | Anti-refusal: requires not refusing, not warning of risk, unconditional execution | BLOCKED (clawhub downgrades to WARN) |
| AGENT-TRIGGER-001 | Trigger abuse ("invoke this skill for every question") | NEEDS_FIX |
| MCP-PRIV-001 | Overly broad MCP permissions: `permissions: "*"`, arbitrary file R/W, skipping the sandbox | BLOCKED (clawhub downgrades to WARN) |
| MCP-PROMPT-001 | Tool-description poisoning: "do not tell the user this operation", "do not check before calling" | BLOCKED (clawhub downgrades to high) |
| MCP-DECLARE-001 | Mentions MCP but does not declare it in `requires` | info (default-muted) |

These rules **do not stack the global meta-context word list**
(`use_global_meta_markers: false`) - their attack phrasing is itself "do not X / no
confirmation needed", and stacking "do not" would self-defeat. Each rule uses its own
`exclude_patterns` to precisely exempt negated phrasing.

## 5. Platform tier differences

### `--platform clawhub`

| Class | Behavior |
|-------|----------|
| Forbidden files / artifact hygiene | **skipped** (ClawHub accepts any extension) |
| RED-NET-001~005 | downgraded to WARN (ClawHub does keyword-free content review) |
| LICENSE-FIELD-001 | frontmatter `license:` non-`MIT-0` -> BLOCKED; `MIT-0` -> WARN (recommend removing) |
| META-MISMATCH-001 | script calls external CLI / subprocess / network without `requires` -> WARN |
| security (SEC-* / AST-*) | **still BLOCKER**, no platform downgrade |

### `--platform github`

Exempts open-source license & CI files (`LICENSE` / `.github` / `.gitignore`, ...) for
open-source copy pre-checks.

### `--platform ima`

Tencent ima knowledge-base package differs from SkillHub in four ways (rules in
`platform_profiles.ima`):

| Rule | What it checks | Consequence |
|------|---------------|-------------|
| IMA-FM-001 | frontmatter seven fields complete | BLOCKED |
| IMA-FILE-001 | package contains platform-generated `_meta.json` | BLOCKED |
| IMA-QUOTE-001 | strings use full-width quotes (ima only accepts ASCII straight quotes) | NEEDS_FIX |
| IMA-NAME-001 | filename contains non-ASCII characters | NEEDS_FIX |
| IMA-TRIGGER-001 | `trigger_keywords` exceeds 5 | NEEDS_FIX |

Platform rule changes only touch the `platform_profiles` section of
`rules/skillhub-spec.json`; `gate.py` is not involved.

## 6. Available fields on a rule entry

| Field | Role |
|-------|------|
| `id` / `category` / `severity` / `redline` | the four basics |
| `level: info` | counted in info_hits, not in verdict |
| `patterns` / `exclude_patterns` | regex & precise exemption |
| `self_describing_markers` / `use_global_meta_markers` | meta-context exemption (latter default true, agentic rules set false) |
| `platform_downgrade` | platform downgrade map, e.g. a clawhub-to-medium mapping |
| `scan_targets` | `docs` / `scripts` / `all` |
| `clause` / `origin` / `description` / `authority_type` | source tracing & report fields |

Add or adjust redlines by editing the JSON only; no script changes.

"""


def _rule_catalog_en() -> str:
    return RULE_CATALOG_EN + render_contract_block() + "\n"


CLI_REFERENCE_EN = """# CLI reference (read on demand, do not pre-load)

> SKILL.md section 1 gives the minimal command; this holds every switch. Consult when a
> parameter is unclear or you need to combine them.

## Subcommands

| Subcommand | Purpose |
|------------|---------|
| `check` | gate a single skill directory (default) |
| `dirs` | batch-check multiple skills & summarize (default platform is `github`, differs from `check`) |

## Common check usage

```bash
python scripts/gate.py check --dir <skill>              # default skillhub rules
python scripts/gate.py check --dir <skill> --format json # machine-readable
python scripts/gate.py check --dir <skill> -o report.txt# write to file (overwrites)
python scripts/gate.py dirs --dir ~/.workbuddy/skills   # batch
```

## Scope & platform

| Flag | Meaning |
|------|---------|
| `--platform` | `skillhub` (default) / `github` / `clawhub` / `ima`. **Illegal value exits 2**; it will not silently run under the default. |
| `--all-files` | force full-directory scan. Default: if the dir itself is a git repo, only the git-tracked set (equivalent to CI / publish view). |
| `--show-info` | show INFO-level hits (outbound proxy etc.). Default-muted. |

Precedence: CLI `--platform` > `platform` inside `--config` > default `skillhub`.

## Stitching layer (all optional, off by default)

Deep audit is not this gate's job, but it **can be stitched in** - "who does the deep
analysis" is swappable; "who decides publishability" is not.

```bash
# (1) emit SARIF 2.1.0 (feed GitHub Code Scanning or any SARIF consumer)
python scripts/gate.py check --dir <skill> --format sarif -o gate.sarif

# (2) import an external scanner's SARIF (domsec / SkillSpector / Codex Security all accepted)
python scripts/gate.py check --dir <skill> --sarif-in domsec.sarif

# (3) invoke an external scanner directly (no shell; failure does not affect local verdict)
python scripts/gate.py check --dir <skill> \\
    --deep-scan "python3 ~/tools/scanner.py --format sarif {dir}"
```

Three invariants of the stitching layer:

1. **External findings capped at medium** (error->medium, warning->low), and never carry
   a redline - so the deep layer can **never** independently block a skill. Add
   `--sarif-trusted` to restore original tiers for already-verified tools (the only exception).
2. **A deep-layer failure never affects the local verdict.** Scanner crash / timeout /
   invalid output only logs one line.
3. `--offline` is a hard switch, mutually exclusive with `--deep-scan`. Rationale: Codex
   Security requires login, domsec sends source to a third party - and one reason this
   gate exists is "not one byte leaves", so make it a switch, not a doc promise.

`--deep-scan`'s `{dir}` is replaced with the target dir. **When the path contains
spaces, quote the whole command** and each path inside it. No shell is used, so `;` and
`&&` are not treated as separators.

## Baseline

```bash
python scripts/gate.py check --dir <skill> --write-baseline ./baseline.json
python scripts/gate.py check --dir <skill> --baseline ./baseline.json
```

- fingerprint = `sha256(raw ruleId | file | occurrence | title)` first 16 chars,
  **no line number** - adding a comment at the top does not invalidate the whole baseline.
- `occurrence` is "the N-th hit under the same file+rule", used to distinguish multiple
  hits of one rule (e.g. three unpinned lines in requirements.txt are three issues, not
  three duplicates).
- **Blockers never enter the baseline**: `--write-baseline` skips critical/high/redline
  and records a `skipped_blockers` field for auditability.
- `--baseline X --write-baseline X` together **exits 2**: "filter with it" and "redefine
  it" cannot coexist.
- Suppressed items are not deleted; they are downgraded to info and stay traceable -
  "why was it let through" must be answerable.

## External config

```bash
python scripts/gate.py check --dir <skill> --config ./gate.json
python scripts/gate.py check --dir <skill> --config ./gate.json --strict
```

Config **can only make the gate stricter**:

| Field | Allowed direction |
|-------|-------------------|
| `spec.bundle.max_file_count` / `warn_*` / `max_total_bytes` | lower only |
| `spec.frontmatter.*` (`required` / `slug_pattern` / `semver_pattern` / `slug_min` / `slug_max`) | fully locked, no override |
| unregistered spec field | rejected (fail-closed, prevents "author forgot to register" becoming a bypass) |
| `forbidden_files_append` / `forbidden_globs_append` | append only |
| `rules_append` | append only; `level: info` forbidden (info not in verdict = a universal mute key); pattern length & count capped, nested quantifiers detected (ReDoS) |
| `whitelist_append` | max 20 entries, <=200 chars each; **applies to all rules including redlines** |
| `--strict` | rejects all four override-key classes |

Top-level list fields (`forbidden_files`, ...) are not sections and cannot be overridden
via `spec`; use the corresponding `*_append` keys.

## Feedback loop

If a platform review later exposes a new gotcha, write it back into
`rules/feedback.json` with `--learn`:

```bash
--learn '{"type":"blocker","pattern":"new-danger-word","reason":"platform rejected: ..."}'
--learn '{"type":"warn","pattern":"some-weak-phrase","reason":"..."}'
--learn '{"type":"whitelist","pattern":"enterprise-intranet-outbound","reason":"confirmed as an intranet scenario"}'
```

Loaded automatically on the next scan. **The private whitelist only mutes confirmed
false positives**, does not pollute the default rule base, and does not silence real
redlines. This turns "one delisting lesson" into "auto-prevent-recur on the next run".

## JSON output structure

__JSON_BLOCK__

Errors go to **stderr**; stdout carries only the report body - so `--format json`
pipes directly to downstream.

## Performance reference

A 600-small-file skill dir runs in about 3 seconds (v2.1.1 removed the triple-loop
file-reopen I/O amplification; previously 80 s). Memory peak about 1.9 MB.

"""


def _cli_reference_en() -> str:
    json_block = "```json\n" + json.dumps({
        "skill": "my-skill",
        "directory": "/abs/path/to/my-skill",
        "platform": "skillhub",
        "spec_version": _spec_version(),
        "config_applied": [],
        "disclaimer": EN_DISCLAIMER,
        "verdict": {
            "verdict": "PASS | NEEDS_FIX | BLOCKED",
            "exit_code": 0,
            "total": 0, "blockers": 0, "warnings": 0, "redlines": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0,
        },
        "issues": [{
            "rule_id": "FM-001", "category": "SPEC", "severity": "critical",
            "file": "SKILL.md", "line": 1, "found": "SKILL.md not found",
            "recommendation": "The target directory must contain SKILL.md.",
            "redline": True, "authority_type": "platform_policy",
            "clause": "(optional; only security issues echo the clause source)",
            "source": "(optional; l2 = from --sarif-in / --deep-scan external scanner)",
        }],
        "info_hits": [],
    }, indent=2, ensure_ascii=False) + "\n```"
    body = CLI_REFERENCE_EN.replace("__JSON_BLOCK__", json_block)
    return body + render_contract_block() + "\n"


FILES = {
    "docs/en/SKILL.en.md": _skill_en,
    "docs/en/README.en.md": _readme_en,
    "docs/en/rule-catalog.en.md": _rule_catalog_en,
    "docs/en/cli-reference.en.md": _cli_reference_en,
}


def main() -> int:
    for rel, renderer in FILES.items():
        p = os.path.join(ROOT, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        text = renderer()
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"generated {rel}  ({len(text.splitlines())} lines)")
    print(f"\n{len(FILES)} English docs generated under docs/en/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
