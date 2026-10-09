"""G3 专项验证（对抗式审查 建议级）。

修掉的不只是「参数没接上」，还有一个更实际的缺陷：
`cmd_dirs` 此前无论结论如何都 `sys.exit(1)`，于是 CI 里无法区分
「只有建议项（NEEDS_FIX）」与「被阻断（BLOCKED）」——三档契约在批量场景失效。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "..", "scripts", "gate.py")
PY = sys.executable

fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        fails.append(name)


def mkskill(root, name, clean=True):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    fm = ("---\nname: demo\nslug: demo\nversion: 1.0.0\ndisplayName: d\n"
          "description: d\nsummary: d\ntags: [a]\n---\n\n# demo\n")
    with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(fm)
    if not clean:   # 造一个 blocker：未钉版依赖
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("requests\n")
    return d


def run(*argv):
    p = subprocess.run([PY, GATE, *argv], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


print("=== G3-a 批量检出的结论与退出码要对应（修之前恒为 1）===")
BASE = tempfile.mkdtemp(prefix="g3a_")
mkskill(BASE, "clean-one")
code, out, err = run("dirs", "--dir", BASE, "--all-files")
check("全 PASS -> exit 0", code == 0, f"exit={code} out={out[-80:]} err={err[-80:]}")
check("表里有该 skill", "clean-one" in out, out[:200])

BASE2 = tempfile.mkdtemp(prefix="g3b_")
mkskill(BASE2, "warn-one")
# 让它产生 NEEDS_FIX：ClawHub 专属的 META-MISMATCH-001
# （脚本有 subprocess 但 frontmatter 无 requires；该检查默认 skillhub 模式不触发）
os.makedirs(os.path.join(BASE2, "warn-one", "scripts"), exist_ok=True)
with open(os.path.join(BASE2, "warn-one", "scripts", "s.py"), "w", encoding="utf-8") as f:
    f.write("import subprocess\nsubprocess.run(['ls'])\n")
code, out, _ = run("dirs", "--dir", BASE2, "--all-files", "--platform", "clawhub")
check("NEEDS_FIX -> exit 2（不是 1）", code == 2, f"exit={code} out={out[-120:]}")

BASE3 = tempfile.mkdtemp(prefix="g3c_")
mkskill(BASE3, "blocked-one", clean=False)
code, out, _ = run("dirs", "--dir", BASE3, "--all-files")
check("含 blocker 时非 0", code != 0, f"exit={code}")

print()
print("=== G3-b 三档契约与 check 一致（同目录逐个 vs 批量）===")
# 注：声明-内容一致性（脚本有 subprocess 但 frontmatter 无 requires → META-MISMATCH-001）
# 是 ClawHub 平台专属检查，默认 skillhub 模式不触发，所以要显式 --platform clawhub。
for label, expect in (("clean", 0), ("warn", 2)):
    base = tempfile.mkdtemp(prefix="g3d_")
    d = mkskill(base, "s")
    if label == "warn":
        os.makedirs(os.path.join(d, "scripts"), exist_ok=True)
        with open(os.path.join(d, "scripts", "s.py"), "w", encoding="utf-8") as f:
            f.write("import subprocess\nsubprocess.run(['ls'])\n")
    c1, _, _ = run("check", "--dir", d, "--all-files", "--platform", "clawhub")
    c2, _, _ = run("dirs", "--dir", base, "--all-files", "--platform", "clawhub")
    check(f"{label}: check 与 dirs 退出码一致", c1 == c2 == expect, f"check={c1} dirs={c2}")

print()
print("=== G3-c dirs 现在接受 check 的同名参数 ===")
base = tempfile.mkdtemp(prefix="g3e_")
mkskill(base, "s")
for flag in ("--show-info", "--all-files", "--strict", "--offline"):
    code, _, err = run("dirs", "--dir", base, flag)
    check(f"dirs 接受 {flag}", "unrecognized arguments" not in err, err[:100])

print()
print("=== G3-d --config 在批量场景真正生效（不只是被接受）===")
base = tempfile.mkdtemp(prefix="g3f_")
d = mkskill(base, "s")   # 干净 skill：无 requirements / 无脚本，避免其它命中干扰
cfg = os.path.join(base, "cfg.json")
with open(cfg, "w", encoding="utf-8") as f:
    json.dump({"rules_append": [{"id": "DIRS-CFG-001", "severity": "medium",
                                "patterns": ["^# demo$"]}]}, f)
# 对照：不带配置时干净 skill 必须 PASS（验证「增量」确实来自自定义规则）
code0, out0, _ = run("dirs", "--dir", base, "--all-files")
check("不带配置时干净 skill PASS", "s" in out0 and "PASS" in out0, out0[:200])
# 带配置：自定义规则命中 SKILL.md 首行 # demo → 批量结论变为 NEEDS_FIX
code, out, _ = run("dirs", "--dir", base, "--all-files", "--config", cfg)
check("带配置时批量结论变为 NEEDS_FIX", "s" in out and "NEEDS_FIX" in out, out[:200])
# 直接验证自定义规则被并入判定（dirs 表只打计数不打印 rule_id，用 check --format json 看）
cj, oj, _ = run("check", "--dir", d, "--all-files", "--config", cfg, "--format", "json")
check("自定义规则 DIRS-CFG-001 真实并入判定", '"DIRS-CFG-001"' in oj, oj[:300])

print()
print("=== G3-e --strict 锁死规则库对 dirs 同样生效 ===")
bad_cfg = os.path.join(base, "bad.json")
with open(bad_cfg, "w", encoding="utf-8") as f:
    json.dump({"spec": {"bundle": {"max_file_count": 99999}}}, f)
code, _, err = run("dirs", "--dir", base, "--all-files", "--config", bad_cfg, "--strict")
check("dirs --strict 拒绝放宽阈值", code == 2 and "覆盖类配置" in (err + out),
      f"exit={code} err={err[:120]}")

print()
print("=== G3-f --platform 校验在 dirs 生效（拼错不得静默）===")
code, _, err = run("dirs", "--dir", base, "--platform", "clahub")
check("dirs 平台拼错被拒", code == 2 and "未知平台" in (err + out), f"exit={code} err={err[:100]}")
for good in ("skillhub", "github", "clawhub", "ima"):
    code, _, err = run("dirs", "--dir", base, "--platform", good)
    check(f"dirs 平台 {good} 可用", "未知平台" not in (err + out), f"exit={code} err={err[:60]}")

print()
print("=== G3-g 边界 ===")
code, _, err = run("dirs", "--dir", "/nonexistent/g3")
check("不存在的父目录报错", code == 2 and "不是目录" in (err + out), f"exit={code}")
empty = tempfile.mkdtemp(prefix="g3h_")
code, _, err = run("dirs", "--dir", empty)
check("空目录 exit 2 且有提示", code == 2 and "未找到" in (err + out), f"exit={code} err={err[:80]}")

print()
print("=== G3-h check 未被共享参数抽取破坏 ===")
base = tempfile.mkdtemp(prefix="g3i_")
d = mkskill(base, "s", clean=False)
for flag in ("--show-info", "--all-files", "--learn", "--write-baseline", "--offline"):
    code, _, err = run("check", "--dir", d, flag, "--help")
    check(f"check 仍接受 {flag}", "unrecognized arguments" not in err, err[:80])
code, out, _ = run("check", "--dir", d, "--all-files", "--format", "json")
check("check --format json 仍可", code in (0, 1, 2) and '"verdict"' in out, out[:80])
bl = os.path.join(base, "b.json")
code, out, _ = run("check", "--dir", d, "--all-files", "--write-baseline", bl)
check("check --write-baseline 仍可", os.path.exists(bl), out[:120])

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "G3 全部通过 ✅")
print("=" * 60)
sys.exit(1 if fails else 0)