#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2-2 适配器 SDK：把外部扫描器做成「一行 --adapter 接入」的一等公民。

设计目标（对标 A.I.G 的插件化）：domsec / SkillSpector / Codex Security / ClawScan
等外部工具不再需要手抄命令，而是注册成统一契约的适配器：

    scan(target_dir) -> issues

每个适配器只声明三件事：
    · name            唯一标识（CLI 用 --adapter <name>）
    · display_name    报告里给人看的名字
    · command_template 形如 "tool --format sarif {dir}"，{dir} 被替换为目标目录
    · notes           文档/获取方式说明

接入点：
    · adapters.d/*.py 暴露模块级变量 ADAPTER = {...}，注册表自动发现。
    · 本文件内置 _BUILTIN 同名备份，确保即使 adapters.d 缺失也能工作。

统一处理（缝接层语义，与 --sarif-in 一致）：
    · 不经 shell（shlex 拆词 list 传参）
    · 失败不影响 L0 判定（返回空 + note）
    · 外部结果经 sarif_io.from_sarif 导入，按 L2 降一级、标 source="l2"、
      redline=False——深度层永远不能单独把某个 skill 判 BLOCKED（沿用 L2 封顶 medium）。

零依赖：仅标准库 + 复用同目录 sarif_io。永不抛异常（外部工具挂了不该让门禁崩）。
"""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sarif_io  # noqa: E402

_DIR = os.path.dirname(os.path.abspath(__file__))
ADAPTERS_DIR = os.path.join(_DIR, "adapters.d")

# 内置备份：即使 adapters.d 整个被删，--adapter 仍可识别这 4 个名字。
_BUILTIN = {
    "domsec": {
        "name": "domsec",
        "display_name": "domsec (OpenClaw 风险扫描)",
        "command_template": "domsec scan --format sarif {dir}",
        "notes": "OpenClaw 风险：不安全配置/Skill 风险/CVE/隐私泄漏。",
    },
    "skillspector": {
        "name": "skillspector",
        "display_name": "SkillSpector",
        "command_template": "skillspector --sarif {dir}",
        "notes": "技能静态审计，输出 SARIF 2.1.0。",
    },
    "codex_security": {
        "name": "codex_security",
        "display_name": "Codex Security",
        "command_template": "codex-security scan --format sarif {dir}",
        "notes": "OpenAI Codex Security 代码漏洞扫描，SARIF 输出。",
    },
    "clawscan": {
        "name": "clawscan",
        "display_name": "ClawScan",
        "command_template": "clawscan --format sarif {dir}",
        "notes": "OpenClaw 风险扫描（ClawHub 生态）。",
    },
}


def _strip_quotes(a: str) -> str:
    if len(a) >= 2 and a[0] in "\"'" and a[-1] == a[0]:
        return a[1:-1]
    return a


def load_registry() -> dict:
    """返回 {name: adapter_dict}。先扫 adapters.d/，再用 _BUILTIN 补齐缺失项。"""
    registry = dict(_BUILTIN)
    if not os.path.isdir(ADAPTERS_DIR):
        return registry
    for fn in sorted(os.listdir(ADAPTERS_DIR)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        path = os.path.join(ADAPTERS_DIR, fn)
        try:
            spec = importlib.util.spec_from_file_location("spg_adapter_" + fn[:-3], path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception:  # noqa: BLE001
            continue
        adapter = getattr(mod, "ADAPTER", None)
        if isinstance(adapter, dict) and adapter.get("name"):
            registry[adapter["name"]] = adapter
    return registry


def run_adapter(adapter: dict, target_dir: str, timeout: int = 600) -> dict:
    """执行单个适配器并把其 SARIF 输出转成 issue 列表。

    返回 {"issues": [...], "notes": [...]}。任何异常都降级为空结果 + note，
    由调用方记为 INFO（与 run_deep_scan 的「深度层失败不染红 L0」同义）。"""
    result = {"issues": [], "notes": []}
    command = adapter.get("command_template", "")
    if not command or "{dir}" not in command:
        result["notes"].append(
            f"适配器 {adapter.get('name')} 缺少含 {{dir}} 的 command_template，已跳过")
        return result
    raw = command.replace("\\", "/") if os.name == "nt" else command
    try:
        argv = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError as exc:
        result["notes"].append(f"适配器 {adapter.get('name')} 命令无法解析：{exc}")
        return result
    argv = [_strip_quotes(a) for a in argv]
    if not argv:
        result["notes"].append(f"适配器 {adapter.get('name')} 为空命令，已跳过")
        return result
    argv = [a.replace("{dir}", target_dir) for a in argv]
    try:
        proc = subprocess.run(argv, cwd=target_dir, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        result["notes"].append(
            f"适配器 {adapter.get('name')} 找不到可执行：{argv[0]}（未安装不影响 L0）")
        return result
    except subprocess.TimeoutExpired:
        result["notes"].append(f"适配器 {adapter.get('name')} 超时（>{timeout}s）已中止")
        return result
    except OSError as exc:
        result["notes"].append(f"适配器 {adapter.get('name')} 执行失败：{exc}")
        return result
    if proc.returncode != 0:
        result["notes"].append(
            f"适配器 {adapter.get('name')} 退出码 {proc.returncode}，结果未纳入判定"
            f"（stderr: {(proc.stderr or '').strip()[:120]}）")
    stdout = (proc.stdout or "").strip()
    if not stdout:
        result["notes"].append(
            f"适配器 {adapter.get('name')} 无 stdout 输出，无 SARIF 可导入")
        return result
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as exc:
        result["notes"].append(
            f"适配器 {adapter.get('name')} 输出非合法 JSON（{exc}），已忽略")
        return result
    issues = sarif_io.from_sarif(doc, trusted=False, source="l2")
    result["issues"] = issues
    result["notes"].append(
        f"适配器 {adapter.get('name')} 导入 {len(issues)} 条 finding（已降一级）")
    return result


def scan_with_adapter(name: str, target_dir: str, timeout: int = 600) -> dict:
    """按名字查注册表并运行；名字不存在返回空 + note。"""
    registry = load_registry()
    adapter = registry.get(name)
    if not adapter:
        return {"issues": [],
                "notes": [f"未知适配器 {name}（可用：{', '.join(sorted(registry))}）"]}
    return run_adapter(adapter, target_dir, timeout=timeout)
