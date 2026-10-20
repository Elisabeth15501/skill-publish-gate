# -*- coding: utf-8 -*-
"""P1-2 复验：T09 本地 deep 模式（INSEC-* 规则）。

恶意代码样本（scripts/*.py）应被对应 INSEC-* 规则命中；
良性样本（env 读取 / 占位值）不应误报。
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


def run(target, *extra):
    p = subprocess.run([PY, GATE, "check", "--dir", target, "--all-files",
                        "--format", "json", *extra],
                       capture_output=True, text=True)
    try:
        return json.loads(p.stdout), p.returncode, p.stderr
    except json.JSONDecodeError:
        return None, p.returncode, (p.stderr or "") + (p.stdout or "")


def skill_with_script(name, pyname, code):
    """最小合法 skill + 一个 scripts/<pyname>.py。"""
    d = tempfile.mkdtemp(prefix=f"p1b_{name}_")
    slug = name.replace("_", "-")
    fm = ("---\nname: %s\nslug: %s\nversion: 1.0.0\ndisplayName: d\n"
          "description: d\nsummary: d\ntags: [a]\n---\n\n# %s\n" % (slug, slug, slug))
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(fm)
    sd = os.path.join(d, "scripts")
    os.makedirs(sd, exist_ok=True)
    open(os.path.join(sd, pyname), "w", encoding="utf-8").write(code + "\n")
    return d


def has_rule(data, rid):
    return any(i.get("rule_id") == rid for i in data.get("issues", []))


print("=== P1-2 恶意代码：应命中对应 INSEC-* 规则 ===")

cases = [
    ("crypto", "weak.py",
     "import hashlib\nprint(hashlib.md5(b'x').hexdigest())",
     "INSEC-CRYPTO-001", "medium"),
    ("ssrf", "ssrf.py",
     'import requests\nrequests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials")',
     "INSEC-SSRF-001", "high"),
    ("traversal", "trav.py",
     'import os\npath = os.path.join(req.args.get("f"), "../etc/passwd")',
     "INSEC-TRAVERSAL-001", "medium"),
    ("tmprace", "tmp.py",
     "import tempfile\nfn = tempfile.mktemp()",
     "INSEC-TMPRACE-001", "low"),
    ("hardcoded_conn", "cred.py",
     'DB = "postgres://admin:secretpass@db.local:5432/app"',
     "INSEC-HARDCODED-001", "high"),
    ("hardcoded_pw", "pw.py",
     'password = "hunter2xyz"',
     "INSEC-HARDCODED-002", "medium"),
]
for tag, pyname, code, rid, sev in cases:
    d = skill_with_script(tag, pyname, code)
    data, code_rc, err = run(d)
    blocked = data and data["verdict"]["verdict"] == "BLOCKED"
    ok = data and has_rule(data, rid)
    if sev in ("high",):
        ok = ok and blocked
    check(f"{tag}: {rid} 命中（severity={sev}）", ok,
          (data["verdict"] if data else err[:120]))

print()
print("=== P1-2 良性代码：不应误报 ===")

benign = [
    ("b_env_pw", "pw.py",
     'password = os.environ["DB_PASSWORD"]', "INSEC-HARDCODED-002"),
    ("b_placeholder", "pw2.py",
     'password = "changeit"  # 占位，部署时替换', "INSEC-HARDCODED-002"),
    ("b_secure_hash", "dedup.py",
     "import hashlib\nh = hashlib.sha256(data).hexdigest()  # 安全哈希", "INSEC-CRYPTO-001"),
    ("b_realpath", "safe.py",
     'import os\np = os.path.realpath(os.path.join(base, name))', "INSEC-TRAVERSAL-001"),
    ("b_mkstemp", "tmpok.py",
     "import tempfile\nfd, fn = tempfile.mkstemp()", "INSEC-TMPRACE-001"),
]
for tag, pyname, code, rid in benign:
    d = skill_with_script(tag, pyname, code)
    data, code_rc, err = run(d)
    ok = data and not has_rule(data, rid)
    check(f"{tag}: {rid} 未误报", ok, (data["verdict"] if data else err[:120]))

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "P1-2 T09 本地 deep 模式全部通过 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
