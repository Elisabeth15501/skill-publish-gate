#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stdlib ast 薄兜底：给「危险调用」一个精确行号。

定位（v3 修订后的 C1′）：**只做薄兜底，不做污点追踪**。
  - 污点追踪（数据从哪来、流到哪个 sink）是通用代码安全域，Codex Security /
    SkillSpector / domsec 都在做，自己写等于在别人主场重复造。
  - 但「这个文件第 47 行调了 eval」这件事，正则给不出行号、给不出「是调用还是
    注释还是字符串」，而它恰恰是门禁最该报给人看的一条。用 stdlib ast 三十行
    就能做到，所以这一层值得自己写。

判定口径（刻意保守，宁可漏报不可误报）：
  - 只报**明确的调用节点**，不猜语义。`eval` 出现在注释里、字符串里、函数名里
    都不算；`x.eval()` 这种属性访问也不算（除非基名就在危险名单里）。
  - 每条 finding 都带 code（源码行原文），报告里直接可核对，不给人「凭什么是它」
    的疑问成本。
  - 文件解析失败（语法错误 / 非 UTF-8 / Python2 语法）只记 note，不抛异常——
    门禁不该因为目标文件有语法错误就崩掉。

豁免：行内含 `# noqa` / `# nosec` / `# gate: allow` 时跳过。这不是放水，
而是让「我确认过、这里安全」能被写在代码里，这是所有静态分析工具的通用做法。
"""

from __future__ import annotations

import ast
import os
import re

# 危险调用表。分三类，因为「什么算危险」完全取决于调用者是谁：
#   BARE      —— 内建名字，任何限定形式都危险（eval / exec / compile）
#   DOTTED    —— 只有特定模块路径才危险。这一类是误报重灾区：
#                json.loads 每次解析配置文件都在用，把它报成高危会让工具被立刻关掉
#   SHELL_ARG —— 由参数而非函数名决定危险（shell=True）
# 内建名字：任何限定形式都危险（x.eval() / eval() / a.b.eval() 都算）
_BARE_CALLS = {
    "eval": ("high", "AST-EVAL-001",
             "eval 执行运行时构造的字符串，等于把代码执行权交给数据",
             "改用 ast.literal_eval（只解析字面量）；确需动态执行请说明输入来源为何可信。"),
    "exec": ("high", "AST-EXEC-001",
             "exec 执行运行时构造的代码块",
             "拆成显式函数调用；确需动态执行请说明输入来源为何可信。"),
}

# compile 单独一档：单独用于语法检查是安全的，只在与 exec/eval 组合时才危险。
# 但静态单文件看不出组合关系，所以保持 medium，由人判断。
_COMPILE_CALL = ("compile", "medium", "AST-COMPILE-001",
                 "compile 后接 exec/eval 会形成动态执行链",
                 "仅做语法检查可保留；若参与执行链请改为显式调用。")

# 反序列化：只列真正能实例化任意类的加载器
_DOTTED_CALLS = {
    "pickle.loads": ("high", "AST-PICKLE-001",
                     "pickle.loads 反序列化可执行任意代码，且能被畸形数据直接打挂",
                     "只加载可信来源；必须反序列化不可信数据时改用 json。"),
    "pickle.load": ("high", "AST-PICKLE-001",
                    "pickle.load 反序列化可执行任意代码",
                    "只加载可信来源；必须反序列化不可信数据时改用 json。"),
    "dill.loads": ("high", "AST-PICKLE-001",
                   "dill.loads 可反序列化任意代码对象",
                   "只加载可信来源；改用 json。"),
    "marshal.loads": ("medium", "AST-MARSHAL-001",
                      "marshal.loads 解析不可信输入可导致崩溃或内存耗尽",
                      "改用 json 等数据格式。"),
    "os.system": ("high", "AST-OS-001",
                  "os.system 走 shell 解释，参数含用户输入即等于命令注入",
                  "改用 subprocess.run([...]) 列表形式并传 shell=False。"),
    "os.popen": ("high", "AST-OS-001",
                 "os.popen 走 shell 解释，参数含用户输入即等于命令注入",
                 "改用 subprocess.run([...]) 列表形式并传 shell=False。"),
}

_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True", re.I)
_YAML_UNSAFE_RE = re.compile(r"yaml\.load\s*\((?![^)]*Safe)", re.I)
_ALLOW_COMMENT_RE = re.compile(r"#\s*(noqa|nosec|gate:\s*allow)", re.I)
_SHELL_MODULES_RE = re.compile(r"^(subprocess|os|commands|popen2)\b")


class GuardResult(dict):
    """findings 列表 + note 列表的轻量容器。

    用 dict 子类而非 tuple，是为了让 gate.py 侧读起来是 r["findings"] 而不是
    「记得第一个返回什么、第二个是什么」——后者是审计必挑的点。
    """


def scan_source(text: str, rel_path: str) -> GuardResult:
    """扫一份 Python 源码，返回 findings 与 notes。永不抛异常。"""
    findings, notes = [], []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return GuardResult(
            findings=findings,
            notes=[{"file": rel_path, "line": exc.lineno or 1,
                    "text": f"无法解析（语法错误）：{exc.msg}"}],
        )
    except (ValueError, RecursionError, MemoryError) as exc:
        # ValueError: 源码含 NUL 等；RecursionError: 深层嵌套
        return GuardResult(
            findings=findings,
            notes=[{"file": rel_path, "line": 1,
                    "text": f"无法解析：{type(exc).__name__}"}],
        )

    lines = text.splitlines()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        line_no = getattr(node, "lineno", 1)
        src = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        if not src or _ALLOW_COMMENT_RE.search(src):
            continue
        hit = _match_dangerous(_dotted(node.func), src)
        if hit:
            severity, rule_id, why, fix = hit
            findings.append({
                "rule_id": rule_id, "severity": severity, "file": rel_path,
                "line": line_no, "found": src[:80], "recommendation": fix,
                "why": why,
            })
    return GuardResult(findings=findings, notes=notes)


def scan_file(abs_path: str, rel_path: str) -> GuardResult:
    """读文件并扫；读不到（权限/编码）只记 note。"""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            return scan_source(f.read(), rel_path)
    except OSError as exc:
        return GuardResult(findings=[], notes=[
            {"file": rel_path, "line": 1, "text": f"读取失败：{exc.strerror or exc}"},
        ])


def scan_skill(target_dir: str) -> GuardResult:
    """扫一个 skill 目录下 scripts/*.py 的全部结果（聚合入口）。"""
    findings, notes = [], []
    script_dir = os.path.join(target_dir, "scripts")
    if not os.path.isdir(script_dir):
        return GuardResult(findings=findings, notes=notes)
    for name in sorted(os.listdir(script_dir)):
        if not name.endswith(".py"):
            continue
        result = scan_file(os.path.join(script_dir, name), f"scripts/{name}")
        findings += result["findings"]
        notes += result["notes"]
    return GuardResult(findings=findings, notes=notes)


# ═══════════════════════════════════════════════════════════════
#  内部
# ═══════════════════════════════════════════════════════════════

def _match_dangerous(dotted: str, src: str) -> tuple:
    """判断一次调用是否命中危险表，返回 (severity, rule_id, why, fix) 或 None。

    判定全部基于还原后的点号路径，不猜语义、不看变量来源。
    """
    if dotted in _DOTTED_CALLS:
        return _DOTTED_CALLS[dotted]
    if dotted in _BARE_CALLS:
        return _BARE_CALLS[dotted]
    if dotted == _COMPILE_CALL[0]:
        return _COMPILE_CALL
    if _SHELL_TRUE_RE.search(src) and _SHELL_MODULES_RE.match(dotted):
        return ("high", "AST-SHELL-001",
                "以 shell=True 调外部命令，参数拼接即等于命令注入",
                "改用列表形式参数 + shell=False；确需 shell 时严格校验每个参数。")
    if _YAML_UNSAFE_RE.search(src):
        return ("medium", "AST-YAML-001",
                "yaml.load 未指定 SafeLoader，可构造对象实例化任意类",
                "改用 yaml.safe_load。")
    if re.search(r"__import__\s*\(", src):
        return ("medium", "AST-IMPORT-001",
                "__import__ 动态导入，绕过静态依赖审计",
                "改用常规 import 语句，让依赖能被静态分析看见。")
    return None


def _dotted(func) -> str:
    """还原点号路径（`os.path.join` → "os.path.join"），非点号形式返回空串。"""
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))
