# -*- coding: utf-8 -*-
"""P1-4 基准 harness：自报 SPG 对 A.I.G 9 类 + 平台规范的检测力。

读取 tests/bench/cases.json（known-good / known-bad / ambiguous 语料），
逐个物化为临时 skill 跑 gate.py check，按标签统计：
  TP = 已知坏 被命中(≥1 issue)
  FN = 已知坏 未被命中
  FP = 已知好 被命中(≥1 issue)
  TN = 已知好 未被命中
  Precision = TP/(TP+FP)   Recall = TP/(TP+FN)
  F1 = 2·P·R/(P+R)         FPR = FP/(FP+TN)
ambiguous 不参与 2×2，仅单独报告（衡量边界稳定性）。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.normpath(os.path.join(HERE, "..", "scripts", "gate.py"))
CASES = os.path.join(HERE, "bench", "cases.json")
PY = sys.executable


def build_skill(case):
    d = tempfile.mkdtemp(prefix=f"bench_{case['id']}_")
    slug = case.get("slug_override") or case["id"].replace("_", "-")
    fm = ("---\nname: %s\nslug: %s\nversion: 1.0.0\ndisplayName: d\n"
          "description: d\nsummary: d\ntags: [a]\n---\n\n# %s\n\n" % (slug, slug, slug))
    body = case.get("doc", "占位正文。")
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(fm + body + "\n")
    for rel, content in case.get("files", {}).items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p) or d, exist_ok=True)
        open(p, "w", encoding="utf-8").write(content)
    if case.get("gen") == "obfuscate":
        # 运行时生成 base64 混淆载荷：解码后为 `os.system("id")` 触发反混淆层
        import base64
        payload = base64.b64encode(b'os.system("id")').decode()
        sp = os.path.join(d, "scripts")
        os.makedirs(sp, exist_ok=True)
        open(os.path.join(sp, "s.py"), "w", encoding="utf-8").write(
            "import base64\n"
            "exec(base64.b64decode(\"%s\").decode())\n" % payload
        )
    return d


def run_gate(d):
    p = subprocess.run([PY, GATE, "check", "--dir", d, "--all-files",
                        "--format", "json"],
                       capture_output=True, text=True)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None, (p.stderr or "")[:200]
    issues = data.get("issues", [])
    return [i.get("rule_id") for i in issues], data.get("verdict", {})


def main():
    doc = json.loads(open(CASES, encoding="utf-8").read())
    cases = doc["cases"]

    tp = fn = fp = tn = 0
    rows = []
    ambiguous = []
    for c in cases:
        d = build_skill(c)
        rids, verdict = run_gate(d)
        if rids is None:
            print("!! 运行失败 %s: %s" % (c["id"], verdict), file=sys.stderr)
            continue
        flagged = len(rids) > 0
        exp = c.get("expected", [])
        hit_expected = [r for r in rids if r in exp] if exp else (rids if flagged else [])
        if c["label"] == "bad":
            if flagged:
                tp += 1
                status = "TP"
            else:
                fn += 1
                status = "FN"
            rows.append((c["id"], c["category"], status, rids or [], exp))
        elif c["label"] == "good":
            if flagged:
                fp += 1
                status = "FP"
            else:
                tn += 1
                status = "TN"
            rows.append((c["id"], c["category"], status, rids or [], exp))
        else:  # ambiguous
            ambiguous.append((c["id"], c["category"], "FLAGGED" if flagged else "clean", rids or []))

    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("=" * 78)
    print("SPG 基准 harness  —  A.I.G 9 类 + 平台规范")
    print("=" * 78)
    print("%-22s %-22s %-5s %s" % ("case", "category", "verdict", "rules fired (expected)"))
    print("-" * 78)
    for cid, cat, status, fired, exp in rows:
        print("%-22s %-22s %-5s %s  exp=%s" % (cid, cat[:22], status, fired, exp))
    print("-" * 78)
    print("ambiguous (不计入 2x2):")
    for cid, cat, status, fired in ambiguous:
        print("  %-22s %-22s %-8s %s" % (cid, cat[:22], status, fired))
    print("=" * 78)
    print("TP=%d FN=%d FP=%d TN=%d" % (tp, fn, fp, tn))
    print("Precision=%.3f  Recall=%.3f  F1=%.3f  FPR=%.3f" % (prec, rec, f1, fpr))
    print("=" * 78)
    # 退出码：F1 达标记 0，否则记 1（供 CI 断言）
    ok = (f1 >= 0.95 and rec >= 0.95 and fpr <= 0.05)
    print("BENCH", "PASS ✅ (F1>=0.95)" if ok else "BELOW TARGET ⚠️")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
