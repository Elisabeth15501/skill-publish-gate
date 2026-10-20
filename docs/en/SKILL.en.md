# Skill Publish Gate (`skill-publish-gate`)

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
| `PASS` | `0` | No issues. Publishable. |
| `NEEDS_FIX` | `2` | Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'. |
| `BLOCKED` | `1` | At least one blocker. Must fix, else rejected or delisted. |

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

This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.
## Machine-verifiable invariants (injected by gen_en_docs.py, do not hand-edit)

- **GATE_VERSION / spec_version**: `3.3.0` (must equal `rules/skillhub-spec.json` `version`)
- **Exit-code contract**: `PASS`=`0` (No issues. Publishable.) | `NEEDS_FIX`=`2` (Warnings only (medium/low). Fix, or explicitly say 'non-blocking but recommended'.) | `BLOCKED`=`1` (At least one blocker. Must fix, else rejected or delisted.)
- **Rule IDs / CLI flags**: authoritative source is `rules/skillhub-spec.json` (`rules[].id`) + `scripts/ast_guard.py` (AST-*) + `scripts/gate.py` argparse; the English docs above mirror the Chinese docs and do not restate the full ID list. Drift is caught by `tests/test_en_docs.py` (recomputes the data source and asserts the invariant block version matches spec.json).
- **English disclaimer**: This gate performs a local spec pre-check and static security scan only. It does NOT constitute a publishing guarantee for any platform. The final publishability is decided by each platform's own review; responsibility lies with the skill author.

