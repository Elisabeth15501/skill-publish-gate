# -*- coding: utf-8 -*-
"""P1-5 复验：report 新增 junit + html 两种格式。

- junit：CI 原生 XML，每条 issue 一个 <failure> testcase；
- html：人读报告，含结论横幅 + 严重度分布 + 命中明细表。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.normpath(os.path.join(HERE, "..", "scripts", "gate.py"))
PY = sys.executable
fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <- {detail}"))
    if not cond:
        fails.append(name)


def run_fmt(target, fmt):
    p = subprocess.run([PY, GATE, "check", "--dir", target, "--all-files",
                        "--format", fmt],
                       capture_output=True, text=True)
    return p.stdout, p.returncode


def skill(name, slug_override=None, body="占位正文。"):
    d = tempfile.mkdtemp(prefix=f"p1rep_{name}_")
    slug = slug_override or name.replace("_", "-")
    fm = ("---\nname: %s\nslug: %s\nversion: 1.0.0\ndisplayName: d\n"
          "description: d\nsummary: d\ntags: [a]\n---\n\n# %s\n\n" % (slug, slug, slug))
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(fm + body + "\n")
    return d


print("=== P1-5 坏样本（下划线 slug 触发 FM-002）应同时出 junit/html ===")

bad = skill("bad_slug", slug_override="bad_slug")  # 下划线 → FM-002
junit, rc_j = run_fmt(bad, "junit")
html, rc_h = run_fmt(bad, "html")

check("junit 含 testsuites 根", "<testsuites" in junit and "</testsuites>" in junit)
check("junit 含 <failure 节点", "<failure" in junit)
check("junit 标注 failures>=1", 'failures="1"' in junit or 'failures="2"' in junit,
      junit[:200])
check("junit 含规则 FM-002", "FM-002" in junit)
check("html 含 DOCTYPE", "<!DOCTYPE html>" in html)
check("html 含结论横幅", "结论" in html and "BLOCKED" in html)
check("html 含严重度分布", "critical" in html and "high" in html)
check("html 含命中明细表行", "FM-002" in html and "<tr>" in html)

print()
print("=== P1-5 干净样本应出空报告（junit failures=0 / html 无问题）===")

good = skill("good_skill", body="本技能用于本地文本整理，不访问网络。")
junit_g, _ = run_fmt(good, "junit")
html_g, _ = run_fmt(good, "html")

check("junit(clean) failures=0", 'failures="0"' in junit_g, junit_g[:200])
check("junit(clean) 无 <failure", "<failure" not in junit_g)
check("html(clean) 未发现规范问题", "未发现规范问题" in html_g)
check("html(clean) 无 FORB/FM 误报", "FORB-001" not in html_g and "FM-002" not in html_g)

print()
# 精确校验 XML 可被解析
import xml.dom.minidom as M
try:
    M.parseString(junit)
    check("junit 可被 minidom 解析", True)
except Exception as e:  # noqa
    check("junit 可被 minidom 解析", False, str(e))

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "P1-5 报告增强（junit + html）全部通过 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
