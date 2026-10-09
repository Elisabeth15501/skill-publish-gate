"""G1/G2 专项验证（对抗式审查 建议级）。

G2 是修掉一个真实漏检：`shell=True` 在多行调用的第二行时，
AST-SHELL-001 整条规则对多行调用完全失效（实测 0 条命中）。

G2 修的过程中还踩到一个回归：`ast.get_source_segment` 对单行调用不含尾部注释、
对多行调用却含——行为不对称，用探针实测确认。断言必须把两种形态都钉住。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import ast_guard  # noqa: E402

fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        fails.append(name)


def scan(text, name="m.py"):
    return [f["rule_id"] for f in ast_guard.scan_source(text, name)["findings"]]


print("=== G2-a 多行 shell=True 必须命中（修之前是 0 条）===")
multi_shell = 'import subprocess\nsubprocess.run(\n    ["ls", "-la"],\n    shell=True,\n)\n'
check("多行 shell=True 命中 AST-SHELL-001", "AST-SHELL-001" in scan(multi_shell),
      scan(multi_shell))

print()
print("=== G2-b 干净的 subprocess 不得误报（多行形态）===")
clean_multi = ('import subprocess\nsubprocess.run(\n    ["ls"],\n'
               '    capture_output=True,\n    check=True,\n)\n')
check("多行干净 subprocess 不报", not scan(clean_multi), scan(clean_multi))

print()
print("=== G2-c noqa 豁免在两种形态下都生效（get_source_segment 行为不对称）===")
check("单行尾注释豁免", not scan("eval(x)  # noqa\n"), scan("eval(x)  # noqa\n"))
check("单行 nosec 豁免", not scan("eval(x)  # nosec\n"), scan("eval(x)  # nosec\n"))
check("单行 gate: allow 豁免", not scan("eval(x)  # gate: allow\n"),
      scan("eval(x)  # gate: allow\n"))
check("多行末行注释豁免",
      not scan('subprocess.run(\n    x,\n    shell=True,  # noqa\n)\n'),
      scan('subprocess.run(\n    x,\n    shell=True,  # noqa\n)\n'))
check("多行首行注释豁免",
      not scan('subprocess.run(  # noqa\n    x,\n    shell=True,\n)\n'),
      scan('subprocess.run(  # noqa\n    x,\n    shell=True,\n)\n'))

print()
print("=== G2-d 跨行 eval / 缩进变体 ===")
check("跨行 eval 命中", "AST-EVAL-001" in scan("result = eval(\n    x\n)\n"),
      scan("result = eval(\n    x\n)\n"))
check("函数内缩进的 shell=True 命中",
      "AST-SHELL-001" in scan(
          'import subprocess\ndef f():\n    return subprocess.run(\n'
          '        ["ls"],\n        shell=True,\n    )\n'),
      scan('import subprocess\ndef f():\n    return subprocess.run(\n        ["ls"],\n        shell=True,\n    )\n'))

print()
print("=== G2-e found 字段应是可读片段而非整块源码 ===")
r = ast_guard.scan_source(multi_shell, "m.py")
found = r["findings"][0]["found"] if r["findings"] else ""
check("found 含 shell=True", "shell=True" in found, found[:60])
check("found 已截断到 80 字符", len(found) <= 80, len(found))

print()
print("=== G1 全量遍历：src/ 与嵌套目录不得漏（修之前只扫 scripts 顶层）===")
D = tempfile.mkdtemp(prefix="g1_")
for sub in ("scripts", "src", os.path.join("scripts", "sub")):
    os.makedirs(os.path.join(D, sub), exist_ok=True)
    with open(os.path.join(D, sub, "m.py"), "w", encoding="utf-8") as f:
        f.write("eval('1')\n")
res = ast_guard.scan_skill(D)
hit = sorted({f["file"] for f in res["findings"]})
check("三处目录全扫到", len(hit) == 3, hit)
check("含 src/main.py 形态", any(p.startswith("src/") for p in hit), hit)
check("含嵌套 scripts/sub/", any(p.startswith("scripts/sub/") for p in hit), hit)

print()
print("=== G1-b 依赖与产物目录必须排除（否则一次 pip install 就去审第三方代码）===")
D2 = tempfile.mkdtemp(prefix="g1b_")
for junk in ("__pycache__", ".venv", "node_modules", ".git", "site-packages",
             "dist", "build", ".pytest_cache", ".mypy_cache", "venv", ".workbuddy"):
    os.makedirs(os.path.join(D2, junk), exist_ok=True)
    with open(os.path.join(D2, junk, "x.py"), "w", encoding="utf-8") as f:
        f.write("eval('1')\n")
os.makedirs(os.path.join(D2, "src"), exist_ok=True)
with open(os.path.join(D2, "src", "ok.py"), "w", encoding="utf-8") as f:
    f.write("eval('1')\n")
res2 = ast_guard.scan_skill(D2)
hit2 = sorted({f["file"] for f in res2["findings"]})
check("11 个垃圾目录全排除、src/ 保留", hit2 == ["src/ok.py"], hit2)

print()
print("=== G1-c 边界 ===")
check("不存在的目录不崩", ast_guard.scan_skill("/nonexistent/g1")["findings"] == [])
check("空目录不崩", ast_guard.scan_skill(tempfile.mkdtemp())["findings"] == [])
D3 = tempfile.mkdtemp(prefix="g1c_")
with open(os.path.join(D3, "broken.py"), "w", encoding="utf-8") as f:
    f.write("def (\n")   # 语法错误
res3 = ast_guard.scan_skill(D3)
check("语法错误记 note 不崩",
      not res3["findings"] and any("语法错误" in n["text"] for n in res3["notes"]),
      res3["notes"])

print()
print("=== G1-d iter_python_files 是可复用接口（供 gate 侧对齐口径）===")
files = ast_guard.iter_python_files(D)
check("返回 (abs, rel) 二元组", all(isinstance(p, tuple) and len(p) == 2 for p in files),
      files[:2])
check("rel 路径用正斜杠", all("\\" not in rel for _, rel in files), files[:2])

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "G1 + G2 全部通过 ✅")
print("=" * 60)
sys.exit(1 if fails else 0)