# Rule catalog (read on demand, do not pre-load)

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

## Machine-verifiable invariants (injected by gen_en_docs.py, do not hand-edit)

- **GATE_VERSION / spec_version**: `3.3.0` (must equal `rules/skillhub-spec.json` `version`)
- **Exit-code contract**: `PASS`=`0` (No issues. Publishable.) | `NEEDS_FIX`=`2` (Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'.) | `BLOCKED`=`1` (At least one blocker. Must fix, else rejected or delisted.)
- **Rule IDs / CLI flags**: authoritative source is `rules/skillhub-spec.json` (`rules[].id`) + `scripts/ast_guard.py` (AST-*) + `scripts/gate.py` argparse; the English docs above mirror the Chinese docs and do not restate the full ID list. Drift is caught by `tests/test_en_docs.py` (recomputes the data source and asserts the invariant block version matches spec.json).
- **English disclaimer**: This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.

