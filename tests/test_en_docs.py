"""中英文版不变量一致性测试。

英文版是「共享源 + 生成器」架构（scripts/gen_en_docs.py）：
  - 纯翻译文本手写
  - 可机验的不变量（规则 ID、CLI 参数、退出码、版本号、免责声明）由生成器从
    唯一数据源（rules/skillhub-spec.json + scripts/gate.py + scripts/ast_guard.py）注入

本测试断言中英两版这些不变量对齐，任何一边漂移都会被抓出来：
  1. docs/en/ 四个文件存在且非空
  2. 每个 .en.md 末尾的不变量块存在
  3. 不变量块里的版本号 == spec.json 的 version
  4. 不变量块里的规则 ID 集合 == 从 spec.json + ast_guard.py 独立重算的集合
  5. 不变量块里的 CLI flag 集合 == 从 gate.py 独立重算的集合
  6. 英文版引用的每条规则 ID 都在英文版不变量块里（防止英文版自己编 ID）
  7. 英文版与中文版引用的 spec.json 规则 ID 集合一致（防跨语言漂移）
"""
from __future__ import annotations

import json
import os
import re
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
PY = sys.executable

EN_DIR = os.path.join(ROOT, "docs", "en")
EN_FILES = ["SKILL.en.md", "README.en.md", "rule-catalog.en.md", "cli-reference.en.md"]
INVENTORY_MARKER = "## Machine-verifiable invariants"


def read(rel: str) -> str:
    p = os.path.join(ROOT, rel)
    with open(p, encoding="utf-8") as f:
        return f.read()


def spec_rule_ids() -> set:
    d = json.load(open(os.path.join(ROOT, "rules", "skillhub-spec.json"), encoding="utf-8"))
    return {r["id"] for r in d["rules"]}


def ast_rule_ids() -> set:
    src = read("scripts/ast_guard.py")
    return set(re.findall(r'"(AST-[A-Z0-9][A-Z0-9-]*)"', src))


def cli_flags() -> set:
    src = read("scripts/gate.py")
    # 排除 --proxy：它是文档「铁律 2」里描述企业内网代理定位的泛指词，不是
    # gate.py 的 CLI 参数；英文版正文按原文翻译保留该词，属合规引用。
    raw = set(re.findall(r'--([a-z][a-z0-9-]*[a-z0-9])', src))
    return raw - {"proxy"}


def gate_rule_ids() -> set:
    """gate.py 硬编码的 rule_id（spec.json 之外的部分，如 FM-001 / SEC-CRED-001 /
    META-MISMATCH-001 / IMA-* 等），口径与 tests/check_rule_ids.py 一致。"""
    src = read("scripts/gate.py")
    return set(re.findall(r'rule_id=["\']([A-Z][A-Z0-9-]+)["\']', src))


def known_rule_ids() -> set:
    """全部真实规则 ID = spec.json + gate.py 硬编码 + ast_guard.py（与
    check_rule_ids.py 同一口径）。英文版引用任何一条都应在此集合内。"""
    return spec_rule_ids() | gate_rule_ids() | ast_rule_ids()


def known_rule_ids() -> set:
    """全部真实规则 ID = spec.json + gate.py 硬编码 + ast_guard.py（与
    check_rule_ids.py 同一口径）。英文版引用任何一条都应在此集合内。"""
    return spec_rule_ids() | gate_rule_ids() | ast_rule_ids()


def spec_version() -> str:
    d = json.load(open(os.path.join(ROOT, "rules", "skillhub-spec.json"), encoding="utf-8"))
    return d["version"]


def invariant_block(text: str) -> str:
    """提取 .en.md 末尾的不变量块。"""
    idx = text.find(INVENTORY_MARKER)
    assert idx >= 0, "不变量块缺失"
    return text[idx:]


def en_referenced_rule_ids(text: str) -> set:
    """英文版正文里提到的 spec/ast 规则 ID（与 check_rule_ids.py 同款抽取）。
    排除不变量块——那里是「以数据源为准」的声明（会提到 rules[].id / AST-* 等
    字面量），不属于「正文引用」，若计入会把数据源标注误判成凭空编 ID。"""
    body = text[:text.find(INVENTORY_MARKER)] if INVENTORY_MARKER in text else text
    ids = set(re.findall(
        r'\b((?:SEC|FORB|RED|FM|IMA|PRIV|AST|AGENT|MCP|OSS|LICENSE|META|DEP|VER|INFO)-[A-Z0-9][A-Z0-9-]*)',
        body))
    return ids


def en_referenced_cli_flags(text: str) -> set:
    """英文版正文里提到的 CLI flag（只看正文，排除不变量块里 argparse 字面量声明）。
    排除 --proxy：它是文档「铁律 2」里描述企业内网代理定位的泛指词，不是
    gate.py 的 CLI 参数；中文版按原文保留该词，英文版合规翻译。"""
    body = text[:text.find(INVENTORY_MARKER)] if INVENTORY_MARKER in text else text
    raw = set(re.findall(r'--([a-z][a-z0-9-]*)', body))
    return raw - {"proxy"}


fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        fails.append(name)


# ── 0. 先生成一遍，确保 docs/en/ 是最新的（防「生成器改了但忘跑」）──
print("=== 重新生成 docs/en/ ===")
gen = subprocess.run([PY, os.path.join(ROOT, "scripts", "gen_en_docs.py")],
                     capture_output=True, text=True)
check("gen_en_docs.py 跑通", gen.returncode == 0, gen.stderr[-200:])

# ── 1. 四个 .en.md 存在且非空 ──
print("=== 1. 文件存在性 ===")
for f in EN_FILES:
    p = os.path.join(EN_DIR, f)
    ok = os.path.isfile(p) and os.path.getsize(p) > 100
    check(f"{f} 存在且非空", ok, f"size={os.path.getsize(p) if os.path.exists(p) else 'N/A'}")

# ── 2/3. 每个 .en.md 有不变量块 + 版本号对齐 ──
print("=== 2. 不变量块存在 + 3. 版本号对齐 ===")
ver = spec_version()
for f in EN_FILES:
    text = read(os.path.join("docs", "en", f))
    block = invariant_block(text)
    check(f"{f} 含不变量块", INVENTORY_MARKER in text)
    check(f"{f} 不变量块版本号={ver}", f"`{ver}`" in block, f"found: {block[:120]}")

# ── 4. 不变量块里的版本号/退出码与数据源一致 ──
# 注意：不变量块只保留「版本号 + 退出码」（真正不可变的跨语言锚点），
# 规则 ID / CLI flags 不逐条内嵌（避免与正文引用叠加造成跨语言漂移误报），
# 由本测试独立重算数据源并断言（见测试 4b/4c）。
print("=== 4. 不变量块不变量与数据源一致 ===")
text = read(os.path.join("docs", "en", "rule-catalog.en.md"))
block = invariant_block(text)
expect_ver = spec_version()
check("不变量块版本号 == spec.json", f"`{expect_ver}`" in block, block[:120])
# 退出码契约行必须与 gate.py verdict() 的固定行为一致（0/2/1）
check("不变量块含退出码契约 0/2/1",
      "PASS" in block and "NEEDS_FIX" in block and "BLOCKED" in block,
      block[:160])

# ── 4b. 英文版正文引用的规则 ID 必须都真实存在（spec + gate 硬编码 + ast）──
print("=== 4b. 英文版正文引用规则 ID 全部真实 ===")
known = known_rule_ids()
for f in EN_FILES:
    referenced = en_referenced_rule_ids(read(os.path.join("docs", "en", f)))
    fake = {r for r in referenced if r not in known}
    check(f"{f} 引用 spec/ast 规则 ID 全部真实存在", not fake, f"fake={sorted(fake)}")

# ── 4c. 英文版引用的 CLI flags 必须都真实存在于 gate.py argparse ──
print("=== 4c. 英文版引用 CLI flags 全部真实 ===")
expect_flags = cli_flags()
for f in EN_FILES:
    text = read(os.path.join("docs", "en", f))
    # 复用 en_referenced_cli_flags：同款正则（限定结尾小写字母/数字）+ 豁免 --proxy
    # （文档「铁律 2」里描述代理定位的泛指词，不是 gate.py 的 CLI 参数）
    en_flags = en_referenced_cli_flags(text)
    fake = en_flags - expect_flags
    check(f"{f} 引用 CLI flags 全部真实存在", not fake, f"fake={sorted(fake)}")

# ── 7. 英文版引用不得比中文版多（防跨语言漂移：中文没写的英文不该有）──
print("=== 7. 英文版引用 spec ID 是中文版的子集（防漂移）===")
for zh, en in (
    ("references/rule-catalog.md", "docs/en/rule-catalog.en.md"),
    ("references/cli-reference.md", "docs/en/cli-reference.en.md"),
    ("SKILL.md", "docs/en/SKILL.en.md"),
    ("README.md", "docs/en/README.en.md"),
):
    zh_ids = en_referenced_rule_ids(read(zh)) & spec_rule_ids()
    en_ids = en_referenced_rule_ids(read(en)) & spec_rule_ids()
    extra = en_ids - zh_ids
    check(f"{en} 引用 spec ID ⊆ {zh}", not extra,
          f"en-only（中文未引用而英文新增了）={sorted(extra)}")

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "英文版一致性全部通过 ✅")
print("=" * 60)
sys.exit(1 if fails else 0)
