# -*- coding: utf-8 -*-
"""P1-3 复验：MCP 规则从 3 类扩面到 14 类。

11 条新增 MCP 规则（MCP-TRANSPORT/SAMPLE/ROOT/RES/SCHEMA/DYN/CMD/
SECRET/PROMPT-TPL/PKG/LOG）对恶意样本应命中，且对良性样例零误报。
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


def skill(name, body):
    """最小合法 frontmatter + body；slug 用 kebab-case 避免 FM-002 掩盖判定。"""
    d = tempfile.mkdtemp(prefix=f"p1mcp_{name}_")
    slug = name.replace("_", "-")
    fm = ("---\nname: %s\nslug: %s\nversion: 1.0.0\ndisplayName: d\n"
          "description: d\nsummary: d\ntags: [a]\n---\n\n# %s\n\n" % (slug, slug, slug))
    open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8").write(fm + body + "\n")
    return d


def has_rule(data, rid):
    return any(i.get("rule_id") == rid for i in data.get("issues", []))


print("=== P1-3 恶意样本：11 条新增 MCP 规则应各自命中 ===")

# (规则id, 临时skill名, 触发正文)
malicious = [
    ("MCP-TRANSPORT-001", "m_transport", "transport: http"),
    ("MCP-TRANSPORT-001", "m_transport2", "url: http://localhost:8080/mcp"),
    ("MCP-SAMPLE-001", "m_sample", "your-api-key: sk-abcdefgh12345678"),
    ("MCP-SAMPLE-001", "m_sample2", "placeholder-secret: <insert-here>"),
    ("MCP-ROOT-001", "m_root", '"roots": ["/"]'),
    ("MCP-RES-001", "m_res", "resource: file:///etc/passwd"),
    ("MCP-SCHEMA-001", "m_schema", '"type": "any"'),
    ("MCP-DYN-001", "m_dyn", "importlib.import_module(name)"),
    ("MCP-DYN-001", "m_dyn2", "load_tool(dynamic_name)"),
    ("MCP-CMD-001", "m_cmd", "os.system(user_input)"),
    ("MCP-CMD-001", "m_cmd2", "subprocess.run(cmd, shell=True)"),
    ("MCP-SECRET-001", "m_secret", 'api_key: "abcdefgh12345678"'),
    ("MCP-SECRET-001", "m_secret2", "Authorization: Bearer eyJabc123def456ghi"),
    ("MCP-PROMPT-TPL-001", "m_ptpl", 'prompt: "Hello {{ user.name }}"'),
    ("MCP-PKG-001", "m_pkg", "npx -y some-server@latest"),
    ("MCP-LOG-001", "m_log", "print(token)"),
    ("MCP-LOG-001", "m_log2", "log.info(secret)"),
]

# 同一规则可能有多条样本，按 rid 收集命中
hit_rids = set()
for rid, tag, body in malicious:
    d = skill(tag, body)
    data, code, err = run(d)
    ok = data and has_rule(data, rid)
    if ok:
        hit_rids.add(rid)
    check(f"{rid} <- {tag}: 命中", ok, (data["verdict"] if data else err[:120]))

print()
print("=== P1-3 良性样本：接近但合规，不应误报 ===")

benign = [
    ("b_transport", "建议使用 stdio 或带 TLS 的 https/wss 传输。"),
    ("b_sample", "凭据应存放在密钥管理器中，切勿写死。"),
    ("b_root", 'roots 限定为 ./work 子目录，不授予根路径。'),
    ("b_res", "resource 仅指向技能自有 data/ 目录。"),
    ("b_schema", '"type": "string" 且 required 列出字段。'),
    ("b_dyn", "白名单加载：ALLOWED = {'tool_a','tool_b'}。"),
    ("b_cmd", "subprocess.run(['ls', path], shell=False)"),
    ("b_secret", 'api_key: os.environ.get("API_KEY")'),
    ("b_secret2", 'password: "${DB_PASSWORD}"'),
    ("b_ptpl", "prompt 用占位符 {{NAME}}，用户输入做转义。"),
    ("b_pkg", "依赖锁定：some-server==1.2.3。"),
    ("b_log", "log.info('task done')"),
]

for tag, body in benign:
    d = skill(tag, body)
    data, code, err = run(d)
    fired = set(i.get("rule_id") for i in data.get("issues", [])) if data else set()
    mcp_fired = {r for r in fired if r.startswith("MCP-")}
    check(f"{tag}: 无 MCP 误报 (fired={sorted(mcp_fired)})", not mcp_fired,
          (sorted(mcp_fired) if data else err[:120]))

print()
print("=" * 60)
all_mcp_new = [
    "MCP-TRANSPORT-001", "MCP-SAMPLE-001", "MCP-ROOT-001", "MCP-RES-001",
    "MCP-SCHEMA-001", "MCP-DYN-001", "MCP-CMD-001", "MCP-SECRET-001",
    "MCP-PROMPT-TPL-001", "MCP-PKG-001", "MCP-LOG-001",
]
missing = [r for r in all_mcp_new if r not in hit_rids]
if missing:
    print("以下新增 MCP 规则在恶意样本中未被命中：", missing)
    fails.extend(missing)
print(f"失败 {len(fails)} 项" if fails else "P1-3 MCP 14 类扩面全部通过 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
