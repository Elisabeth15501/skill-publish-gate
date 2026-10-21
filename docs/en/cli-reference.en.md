# CLI reference (read on demand, do not pre-load)

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
python scripts/gate.py check --dir <skill> \
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

```json
{
  "skill": "my-skill",
  "directory": "/abs/path/to/my-skill",
  "platform": "skillhub",
  "spec_version": "3.4.0",
  "config_applied": [],
  "disclaimer": "This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.",
  "verdict": {
    "verdict": "PASS | NEEDS_FIX | BLOCKED",
    "exit_code": 0,
    "total": 0,
    "blockers": 0,
    "warnings": 0,
    "redlines": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "issues": [
    {
      "rule_id": "FM-001",
      "category": "SPEC",
      "severity": "critical",
      "file": "SKILL.md",
      "line": 1,
      "found": "SKILL.md not found",
      "recommendation": "The target directory must contain SKILL.md.",
      "redline": true,
      "authority_type": "platform_policy",
      "clause": "(optional; only security issues echo the clause source)",
      "source": "(optional; l2 = from --sarif-in / --deep-scan external scanner)"
    }
  ],
  "info_hits": []
}
```

Errors go to **stderr**; stdout carries only the report body - so `--format json`
pipes directly to downstream.

## Performance reference

A 600-small-file skill dir runs in about 3 seconds (v2.1.1 removed the triple-loop
file-reopen I/O amplification; previously 80 s). Memory peak about 1.9 MB.

## Machine-verifiable invariants (injected by gen_en_docs.py, do not hand-edit)

- **GATE_VERSION / spec_version**: `3.4.0` (must equal `rules/skillhub-spec.json` `version`)
- **Exit-code contract**: `PASS`=`0` (No issues. Publishable.) | `NEEDS_FIX`=`2` (Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'.) | `BLOCKED`=`1` (At least one blocker. Must fix, else rejected or delisted.)
- **Rule IDs / CLI flags**: authoritative source is `rules/skillhub-spec.json` (`rules[].id`) + `scripts/ast_guard.py` (AST-*) + `scripts/gate.py` argparse; the English docs above mirror the Chinese docs and do not restate the full ID list. Drift is caught by `tests/test_en_docs.py` (recomputes the data source and asserts the invariant block version matches spec.json).
- **English disclaimer**: This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.

