# -*- coding: utf-8 -*-
"""P0 修复的端到端复验：用对抗式审查里那三个原始攻击原样重打。"""
import json
import os
import subprocess
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
import tempfile

GATE = os.path.normpath(os.path.join(HERE, "..", "scripts", "gate.py"))
PY = sys.executable
fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <- {detail}"))
    if not cond:
        fails.append(name)


def run(target, *extra):
    p = subprocess.run([PY, GATE, "check", "--dir", target, "--all-files", "--format", "json", *extra],
                       capture_output=True, text=True)
    try:
        return json.loads(p.stdout), p.returncode, p.stderr
    except json.JSONDecodeError:
        return None, p.returncode, (p.stderr or "") + (p.stdout or "")


D = tempfile.mkdtemp(prefix="p0verify_")

print("=== 攻击 B1（原样重打）：配置放宽硬校验 ===")
open(os.path.join(D, "SKILL.md"), "w", encoding="utf-8").write(
    "---\nname: d\nslug: Bad Slug With Spaces\nversion: not-semver\ndisplayName: d\n---\n\n# d\n")
cfg = os.path.join(D, "cfg.json")
open(cfg, "w", encoding="utf-8").write(
    '{"spec": {"frontmatter": {"required": [], "slug_pattern": ".*"}}}')
data, code, err = run(D, "--config", cfg)
check("B1 配置被拒（exit 2）", code == 2, f"exit={code}")
check("B1 报错指明是 frontmatter.required", "frontmatter.required" in err, err[:120])
check("B1 没有产生任何报告（未进入扫描）", data is None, "仍跑完了扫描")

print()
print("=== 攻击 B2：BLOCKED 状态下 --write-baseline ===")
open(os.path.join(D, "SKILL.md"), "w", encoding="utf-8").write(
    "---\nname: demo\nslug: demo\nversion: 1.0.0\ndisplayName: d\n"
    "description: d\nsummary: d\ntags: [a]\n---\n\n# d\n")
open(os.path.join(D, "creds.py"), "w", encoding="utf-8").write(
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
bl = os.path.join(D, "bl.json")
data, code, err = run(D, "--write-baseline", bl)
check("B2 首次运行 BLOCKED", data and data["verdict"]["verdict"] == "BLOCKED",
      data["verdict"] if data else err[:120])
payload = json.load(open(bl, encoding="utf-8"))
check("B2 凭据泄漏未进基线", payload["fingerprints"] == [], payload["fingerprints"])
check("B2 基线自证记录了跳过的 blocker", payload.get("skipped_blockers", 0) >= 1, payload)
check("B2 stderr 明确告知跳过", "跳过" in err and "blocker" in err, err[:160])
data2, code2, _ = run(D, "--baseline", bl)
check("B2 复跑仍 BLOCKED（真问题没被静音）",
      data2 and data2["verdict"]["verdict"] == "BLOCKED",
      data2["verdict"] if data2 else None)

print()
print("=== 攻击 B3：--baseline 与 --write-baseline 同开 ===")
before = open(bl, encoding="utf-8").read()
data3, code3, err3 = run(D, "--baseline", bl, "--write-baseline", bl)
after = open(bl, encoding="utf-8").read()
check("B3 exit 2", code3 == 2, code3)
check("B3 报错指明不能同开", "不能同开" in err3, err3[:140])
check("B3 基线文件字节不变", before == after, "文件被改了")

print()
print("=== 正例：干净 skill 的基线往返仍然可用（别把功能焊死）===")
C = tempfile.mkdtemp(prefix="p0ok_")
open(os.path.join(C, "SKILL.md"), "w", encoding="utf-8").write(
    "---\nname: demo\nslug: demo\nversion: 1.0.0\ndisplayName: d\n"
    "description: d\nsummary: d\ntags: [a]\n---\n\n# d\n")
open(os.path.join(C, "requirements.txt"), "w", encoding="utf-8").write("requests\n")
bl2 = os.path.join(C, "bl.json")
d, code, err = run(C, "--write-baseline", bl2)
check("正例：NEEDS_FIX 时写入基线", d and d["verdict"]["verdict"] == "NEEDS_FIX",
      d["verdict"] if d else err[:120])
p2 = json.load(open(bl2, encoding="utf-8"))
check("正例：DEP-PIN-001 进了基线", len(p2["fingerprints"]) == 1, p2["fingerprints"])
d2, code2, _ = run(C, "--baseline", bl2)
check("正例：复跑被基线抑制 → PASS",
      d2 and d2["verdict"]["verdict"] == "PASS", d2["verdict"] if d2 else None)
check("正例：被抑制项留有指纹可追溯",
      any(i.get("fingerprint") for i in (d2["info_hits"] if d2 else [])))

print()
print("=== S6：--platform 拼错必须报错，不得静默降级 ===")
for bad in ["clahub", "ClawHub", "skillhubs", "IMa", ""]:
    args = ["--platform", bad] if bad else []
    p = subprocess.run([PY, GATE, "check", "--dir", C, "--all-files", "--format", "json", *args],
                       capture_output=True, text=True)
    combined = (p.stderr or "") + (p.stdout or "")
    if bad:
        check(f"平台 {bad!r} 被拒", p.returncode == 2 and "未知平台" in combined,
              f"exit={p.returncode} {combined[:80]}")
    else:
        check("不给 --platform 时用默认 skillhub",
              p.returncode in (0, 2) and '"platform": "skillhub"' in p.stdout,
              combined[:80])
for good in ["skillhub", "github", "clawhub", "ima"]:
    p = subprocess.run([PY, GATE, "check", "--dir", C, "--all-files",
                        "--platform", good, "--format", "json"],
                       capture_output=True, text=True)
    # 只断言「没被当成未知平台拒掉」——具体档位取决于目标目录内容
    # （ima 对不满足七字段的目标判 BLOCKED 是正确行为，不是错误）
    check(f"平台 {good} 可用（未被拒）", "未知平台" not in (p.stderr + p.stdout),
          (p.returncode, (p.stderr or "")[:60]))

print()
print("=== S2：L2 封顶，深度层不能单独阻断 ===")
CLEAN = tempfile.mkdtemp(prefix="p0clean_")
open(os.path.join(CLEAN, "SKILL.md"), "w", encoding="utf-8").write(
    "---\nname: demo\nslug: demo\nversion: 1.0.0\ndisplayName: d\n"
    "description: d\nsummary: d\ntags: [a]\n---\n\n# d\n")
p = subprocess.run([PY, GATE, "check", "--dir", CLEAN, "--all-files", "--format", "json"],
                   capture_output=True, text=True)
check("干净目标本地判定 PASS", json.loads(p.stdout)["verdict"]["verdict"] == "PASS",
      p.stdout[:80])
for lvl, expect in [("error", "medium"), ("warning", "low"), ("note", "low")]:
    sf = os.path.join(CLEAN, f"{lvl}.sarif")
    open(sf, "w", encoding="utf-8").write(json.dumps({"version": "2.1.0", "runs": [
        {"results": [{"ruleId": "R", "level": lvl, "message": {"text": "x"},
                      "locations": [{"physicalLocation": {
                          "artifactLocation": {"uri": "x.py"}, "region": {"startLine": 1}}}]}]}]}))
    p = subprocess.run([PY, GATE, "check", "--dir", CLEAN, "--all-files",
                        "--sarif-in", sf, "--format", "json"], capture_output=True, text=True)
    d = json.loads(p.stdout)
    l2 = [i for i in d["issues"] if i.get("source") == "l2"]
    check(f"level={lvl} -> 档位 {expect} 且不阻断",
          l2 and l2[0]["severity"] == expect and d["verdict"]["verdict"] != "BLOCKED",
          (l2[0]["severity"] if l2 else None, d["verdict"]["verdict"]))
sf = os.path.join(CLEAN, "error.sarif")
p = subprocess.run([PY, GATE, "check", "--dir", CLEAN, "--all-files",
                    "--sarif-in", sf, "--sarif-trusted", "--format", "json"],
                   capture_output=True, text=True)
d = json.loads(p.stdout)
check("--sarif-trusted 是唯一能阻断的例外",
      d["verdict"]["verdict"] == "BLOCKED", d["verdict"])

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "原始攻击 + S2/S6 全部被挡住 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
