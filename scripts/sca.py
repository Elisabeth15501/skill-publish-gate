#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线 SCA（T08）：在「零出网」前提下做软件成分分析。

定位（P0-4）：对标 A.I.G 的「依赖/CVE」扫描，但**不依赖任何在线漏洞库**。
库数据随门禁一起发布在 scripts/vuln-deps.json，因此离线、确定性、可复现。

检查两件事：
  1. typosquat：导入的第三方包名是否仿冒一个知名包（仿冒包几乎必然投毒）。
  2. pinned-CVE：若 skill 用 requirements.txt / pyproject.toml / package.json
     锁了版本，且落在已知漏洞区间，报 high。

设计纪律（与 SPG 一致）：纯标准库、零出网、零密钥、永不抛异常。
本模块只做「成分 + 已知区间」比对，不做语义裁决；是否阻断由 gate.py 决定。

为什么不扫「未锁版本」的第三方包为 BLOCKER：skill 生态里 stdlib-only 是常态，
但有合规第三方依赖（requests/pyyaml）也完全正常。未锁版本只给 medium 提示
（「请固定版本，避免供应链漂移」），锁在漏洞区间才升级为 high。
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "vuln-deps.json")


def _stdlib_names() -> set:
    """取当前解释器的标准库模块名集合；老版本回退到小名单。"""
    names = set()
    try:
        names = set(getattr(sys, "stdlib_module_names", set()))  # py3.10+
    except Exception:  # noqa: BLE001
        names = set()
    # 兜底：最常被误判为第三方的几个
    names.update({"os", "sys", "re", "json", "ast", "pathlib", "subprocess",
                  "shutil", "argparse", "datetime", "typing", "collections",
                  "itertools", "functools", "hashlib", "base64", "zlib",
                  "urllib", "http", "io", "time", "math", "random", "string",
                  "textwrap", "glob", "codecs", "enum", "dataclasses"})
    return names


def parse_version(v: str):
    """把版本串转成可比整数元组；非数字段当 0。永不抛异常。"""
    v = (v or "").strip().lstrip("vV")
    parts = re.split(r"[.\-+]", v)
    out = []
    for p in parts:
        m = re.match(r"\d+", p)
        out.append(int(m.group(0)) if m else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out[:3])


def _in_range(version: str, introduced: str, fixed: str) -> bool:
    """introduced <= version < fixed 视为命中（semver 元组比较）。"""
    v = parse_version(version)
    lo = parse_version(introduced)
    hi = parse_version(fixed)
    return lo <= v < hi


def _collect_imports(target_dir: str, exclude: set = None) -> dict:
    """扫全部 .py，返回 {top_level_module: [(rel_path, line)]}。永不抛异常。

    exclude：技能自身的本地模块名集合（basename 去 .py），这些 import 是门禁
    自己的同目录模块，不是第三方依赖，必须跳过，否则 SCA 会把 ast_guard /
    sarif_io 等自家代码误报成「未声明的第三方依赖」。
    """
    imports: dict = {}
    skip = {".git", "__pycache__", ".venv", "venv", "node_modules",
            ".workbuddy", "site-packages", "dist", "build"}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            ap = os.path.join(root, name)
            rel = os.path.relpath(ap, target_dir).replace("\\", "/")
            try:
                src = open(ap, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                mod = None
                if isinstance(node, ast.Import):
                    for a in node.names:
                        mod = a.name.split(".")[0]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mod = (node.module or "").split(".")[0]
                if mod and (not exclude or mod not in exclude):
                    imports.setdefault(mod, []).append((rel, node.lineno))
    return imports


def _local_module_names(target_dir: str) -> set:
    """收集目标目录下所有 .py 的顶层模块名（去 .py），用于 SCA 跳过自家代码。

    同时把「含 .py 文件的非根目录」视为本地包目录（如 aiweekly / delivery /
    validate_checks 这类包目录）——否则这些自带的包会被误判为第三方依赖。
    """
    names = set()
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in {
            ".git", "__pycache__", ".venv", "venv", "node_modules",
            ".workbuddy", "site-packages", "dist", "build"}]
        for name in files:
            if name.endswith(".py"):
                names.add(name[:-3])
        rel = os.path.relpath(root, target_dir)
        if rel == ".":
            continue
        # 该目录自身含 .py 文件 → 视作本地包（import X 其中 X 是包目录）
        if any(f.endswith(".py") for f in files):
            names.add(os.path.basename(root))
    return names


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-\*]+)", re.I)
_PYPROJECT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*[~=<>!]+\s*[\"']?([A-Za-z0-9_.\-\*]+)", re.I)


def _parse_requirement_files(target_dir: str) -> dict:
    """解析 requirements*.txt / pyproject.toml / package.json 的锁定版本。
    返回 {pkg: version}（取首个命中的版本）。"""
    pinned: dict = {}
    for fname in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        fp = os.path.join(target_dir, fname)
        if not os.path.isfile(fp):
            continue
        try:
            text = open(fp, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        rx = _REQ_RE if fname.startswith("requirements") else _PYPROJECT_RE
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("[") or line.startswith(";"):
                continue
            m = rx.match(line)
            if m:
                pinned.setdefault(m.group(1).lower(), m.group(2))
    # package.json（JS 生态）
    pj = os.path.join(target_dir, "package.json")
    if os.path.isfile(pj):
        try:
            doc = json.load(open(pj, encoding="utf-8"))
            for sec in ("dependencies", "devDependencies"):
                for k, v in (doc.get(sec) or {}).items():
                    if isinstance(v, str) and v.startswith("^") == False:
                        ver = re.sub(r"^[^0-9]*", "", v)
                        pinned.setdefault(k.lower(), ver)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    return pinned


def scan_skill(target_dir: str, db_path: str = None) -> dict:
    """离线 SCA 主入口。返回 {"findings": [...], "notes": [...]}。"""
    db_path = db_path or _DEFAULT_DB
    findings, notes = [], []
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return {"findings": findings,
                "notes": [{"text": f"SCA 漏洞库读取失败：{exc}（跳过依赖扫描）"}]}

    blessed = set(db.get("blessed", []))
    typos = db.get("typosquats", {})
    vuln = db.get("known_vulnerable", {})
    stdlib = _stdlib_names()

    local_mods = _local_module_names(target_dir)
    imports = _collect_imports(target_dir, exclude=local_mods)
    # 声明式豁免：已在 requirements / pyproject 固定版本的三方依赖视为「已声明」，
    # 不再报 SCA-THIRDPARTY（与规则建议一致：声明即可豁免扫描）。
    pinned = _parse_requirement_files(target_dir)
    _IMPORT_TO_PKG = {
        "socks": "pysocks",
        "qcloud_cos": "cos-python-sdk-v5",
        "bs4": "beautifulsoup4",
        "yaml": "pyyaml",
        "crypto": "cryptography",
    }
    declared = {p.lower() for p in pinned}
    for mod, locs in sorted(imports.items()):
        if mod in stdlib or mod in blessed:
            continue
        rel, line = locs[0]
        typ = typos.get(mod.lower())
        if typ:
            findings.append({
                "rule_id": "SCA-TYPOSQUAT-001", "severity": "high",
                "file": rel, "line": line,
                "found": f"import {mod}",
                "recommendation": (
                    f"疑似仿冒包：{mod} 仿冒 {typ}。立即删除并改用官方包 {typ}，"
                    "检查是否已执行过该包的代码。"),
                "why": "typosquat 包几乎必然投毒。",
            })
            continue
        # 已在 requirements / pyproject 固定版本 → 视为已声明，跳过 SCA-THIRDPARTY。
        # 注：typosquat 已在上面拦截，不受声明豁免影响（防止「把仿冒包钉进
        # requirements 来绕过扫描」）。
        if (mod.lower() in declared
                or _IMPORT_TO_PKG.get(mod.lower(), "").lower() in declared):
            continue
        # 普通第三方依赖：未锁版本给 medium 提示
        findings.append({
            "rule_id": "SCA-THIRDPARTY-001", "severity": "medium",
            "file": rel, "line": line,
            "found": f"import {mod}",
            "recommendation": (
                f"{mod} 是第三方依赖。请在 requirements / pyproject 固定版本，"
                "并确认它来自可信源、非 typosquat。"),
            "why": "未声明的第三方依赖会引入供应链漂移与未知漏洞面。",
        })

    for pkg, ver in pinned.items():
        for entry in vuln.get(pkg, []):
            if _in_range(ver, entry.get("introduced", "0"), entry.get("fixed", "999")):
                findings.append({
                    "rule_id": "SCA-CVE-001", "severity": "high",
                    "file": "requirements.txt", "line": 1,
                    "found": f"{pkg}=={ver}",
                    "recommendation": (
                        f"{pkg} {ver} 命中 {entry.get('cve')}（{entry.get('severity')}）。"
                        f"升级到 >= {entry.get('fixed')}。"),
                    "why": entry.get("summary", "已知漏洞版本"),
                })
    return {"findings": findings, "notes": notes}
