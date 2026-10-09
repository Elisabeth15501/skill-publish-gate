"""核对文档里提到的每个规则 ID 是否真实存在于代码或规则库。

背景：我在重写 SKILL.md 时写了 SEC-PERMISSION-001 这条规则，
但它在 gate.py 与 spec.json 里都不存在——是写文档时编的。
本脚本把这类失实一次性找出来。
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")

spec = json.load(open(os.path.join(ROOT, "rules", "skillhub-spec.json"), encoding="utf-8"))
spec_ids = {r["id"] for r in spec["rules"]}

src = open(os.path.join(ROOT, "scripts", "gate.py"), encoding="utf-8").read()
code_ids = set(re.findall(r'rule_id=["\']([A-Z][A-Z0-9-]+)["\']', src))

# AST 规则不在 spec.json 里，而是由 scripts/ast_guard.py 以元组字面量实现：
#   ("high", "AST-EVAL-001", "为什么危险", "怎么改")
# 上面的 rule_id= 正则扫不到这种形态，会把这些 ID 误报成「文档虚构」。
# 单独从 ast_guard.py 抽取 AST-* 字面量，与 gate.py 的硬编码 ID 合并。
ast_src = open(os.path.join(ROOT, "scripts", "ast_guard.py"), encoding="utf-8").read()
ast_ids = set(re.findall(r'"(AST-[A-Z0-9][A-Z0-9-]*)"', ast_src))

code_ids |= ast_ids

real = spec_ids | code_ids

DOCS = ["SKILL.md", "README.md", "references/rule-catalog.md", "references/cli-reference.md"]
claimed = {}
for name in DOCS:
    p = os.path.join(ROOT, name)
    if not os.path.exists(p):
        continue
    text = open(p, encoding="utf-8").read()
    for rid in re.findall(r'\b((?:SEC|FORB|RED|FM|IMA|PRIV|AST|AGENT|MCP|OSS|LICENSE|META|DEP|VER|INFO)-[A-Z0-9][A-Z0-9-]*)', text):
        claimed.setdefault(rid, set()).add(name)

print(f"真实规则 ID（spec {len(spec_ids)} + 代码硬编码 {len(code_ids)}）= {len(real)}")
print(f"文档声称的 ID = {len(claimed)}")
print()

# 规则族前缀（xxx-001 这类通配也要接受）
def covered(rid):
    if rid in real:
        return True
    # SEC-CRED-001 这类：前缀 xxx 存在也算（族级引用）
    fam = rid.rsplit("-", 1)[0]
    return any(r == fam or r.startswith(fam + "-") for r in real)

fake = {r: docs for r, docs in sorted(claimed.items()) if not covered(r)}
if fake:
    print("!! 文档提到但代码/规则库不存在的 ID：")
    for rid, docs in fake.items():
        print(f"   {rid:26} 出现在 {', '.join(sorted(docs))}")
else:
    print("文档声称的规则 ID 全部真实存在 ✅")

print()
print("（对照）代码硬编码的 rule_id 全集：")
print("  " + ", ".join(sorted(code_ids)))