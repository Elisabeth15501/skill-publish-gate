# -*- coding: utf-8 -*-
"""P1-7 验证：跨工具去重是否真生效，且不误伤同规则多处命中。"""
import sys
import os
HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "scripts")))
import sarif_io  # noqa: E402

fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <- {detail}"))
    if not cond:
        fails.append(name)


print("=== P1-7（G4）：跨工具去重 ===")
l0 = {"rule_id": "FORB-001", "file": "a.md", "line": 3, "title": "FORB-001"}
l2 = {"rule_id": "L2-FORB-001", "file": "a.md", "line": 3, "title": "FORB-001"}
kept, dropped = sarif_io.dedupe([dict(l0), dict(l2)])
check("L0 与 L2 报同一件事会折叠", len(dropped) == 1, (len(kept), len(dropped)))
check("保留的是 L0 那条（先到者优先）",
      kept and kept[0]["rule_id"] == "FORB-001", [k["rule_id"] for k in kept])

print()
print("=== 反向：不该折叠的三种情况 ===")
a = {"rule_id": "R1", "file": "a.md", "line": 1, "title": "R1"}
b = {"rule_id": "R2", "file": "a.md", "line": 1, "title": "R2"}
kept2, _ = sarif_io.dedupe([a, b])
check("不同规则不折叠", len(kept2) == 2, len(kept2))

c = {"rule_id": "R1", "file": "a.md", "line": 1, "title": "R1"}
d = {"rule_id": "R1", "file": "b.md", "line": 1, "title": "R1"}
kept3, _ = sarif_io.dedupe([c, d])
check("不同文件不折叠", len(kept3) == 2, len(kept3))

m = [{"rule_id": "DEP", "file": "r.txt", "line": i, "title": "DEP"} for i in (1, 2, 3)]
kept4, dropped4 = sarif_io.dedupe([dict(x) for x in m])
check("同规则同文件 3 处命中不折叠（防漏报）",
      len(kept4) == 3 and not dropped4, (len(kept4), len(dropped4)))

print()
print("=== M1：指纹抗行号漂移 ===")
fp10 = sarif_io.fingerprint("DEP", "r.txt", line=10, title="")
fp11 = sarif_io.fingerprint("DEP", "r.txt", line=11, title="")
check("行号变化不改指纹", fp10 == fp11, (fp10, fp11))
shifted = [{"rule_id": "DEP", "file": "r.txt", "line": i + 1, "title": "DEP"} for i in (1, 2, 3)]
sarif_io.assign_occurrences(shifted)
bl = {sarif_io.issue_fingerprint(x, x.get("occurrence")) for x in shifted}
kept5, _ = sarif_io.apply_baseline([dict(x) for x in shifted], bl)
check("整份基线在行号平移后仍全命中", kept5 == [], len(kept5))

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "P1-7 + M1 全部通过 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
