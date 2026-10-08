#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skill 发布门禁（代码安全 + 平台规范）— skill-publish-gate
==========================================

在 `skillhub publish` 之前，对目标 skill 目录做一次本地门禁检查，
确认它符合 SkillHub 的发布规范（frontmatter 硬校验 + 封禁文件类型 +
包体上限 + 版本一致性 + 内容审核红线 + 隐私泄漏 + 权限声明）。

判据来源（均已实测 / 读 CLI 源码校正）：
  - skillhub-publish 技能：--dry-run 只硬校验 slug/version/displayName
    三字段 + YAML 合法性；正式发布时封禁 .gitignore/.nojekyll/LICENSE/
    __pycache__/*.pyc/.github；超大产物包（>1000 文件）会卡死。
  - SkillHub 三线审核：内容合规过滤 / 深度漏洞扫描 / 模型安全评估。
    内容红线含网络规避敏感词、把功能描述成绕过网络管理限制、
    绝对化宣传用语、需资质的金融类表述。
  - TRACE 评测 T 维度：最小权限、敏感信息保护、国内可用性、中文支持。

退出码（可作 CI gate / pre-publish hook）：
    0 = PASS          无任何 blocker / warning，可放心发布
    2 = NEEDS_FIX     仅有建议项（medium/low），建议修复但不阻断
    1 = BLOCKED       命中 blocker（critical/high / 封禁文件 / frontmatter 硬校验失败）
                    —— 必须修复后才能发布，否则会被 SkillHub 拒绝或下架

v2.1.0 新增（缝接层，全部可选、默认关闭）：
    --format sarif        产出 SARIF 2.1.0（喂 GitHub Code Scanning）
    --sarif-in FILE       导入外部扫描器（domsec/SkillSpector/Codex Security）的 SARIF
    --baseline FILE       抑制「确认过的误报」（跨运行指纹）
    --config FILE         外部配置：阈值 / 封禁文件 / 规则追加（只许更严）
    --deep-scan CMD       调用外部深度扫描器（--offline 下禁用）
    --platform ima        腾讯 ima 知识库包规范

依赖：PyYAML（faithful YAML 解析）。
  脚本会先尝试 `import yaml`；缺失则自动 pip install 到当前解释器；
  若仍不可用，会作为 BLOCKER 报错退出，绝不静默通过。

纯 Python 标准库 + PyYAML。默认路径零出网零密钥（仅 subprocess 跑 git ls-files）；
只有显式 --deep-scan 才会执行外部命令。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ast_guard  # noqa: E402  —— 同目录模块，需先补 sys.path
import config_loader  # noqa: E402
import sarif_io  # noqa: E402

GATE_DISCLAIMER = (
    "免责声明：本门禁仅做本地规范预检，不构成 SkillHub 审核保证。"
    "最终能否上架由 SkillHub 三线审核决定，责任由开发者自行承担。"
)
GATE_VERSION = "2.1.1"


# ═══════════════════════════════════════════════════════════════
#  YAML 解析（faithful parse，带自安装兜底）
# ═══════════════════════════════════════════════════════════════

class YamlUnavailable(RuntimeError):
    pass


class GateConfigError(RuntimeError):
    """外部配置越权/非法。独立于 config_loader.ConfigError 是为了让 CLI 能
    一律按「用户输入错误」处理，不必 import 内部模块的异常类型。"""


def load_yaml_module():
    """返回 yaml 模块；不可用则尝试自安装，再不可用抛 YamlUnavailable。"""
    try:
        import yaml  # type: ignore
        return yaml
    except ImportError:
        pass
    # 自安装兜底（仅在当前解释器内，不污染用户全局环境）
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "pyyaml"],
            check=True,
            capture_output=True,
            timeout=120,
        )
        import yaml  # type: ignore
        return yaml
    except Exception as exc:  # noqa: BLE001
        raise YamlUnavailable(
            "PyYAML 不可用且自动安装失败，无法做 faithful YAML 解析。"
            f"请手动 `pip install pyyaml`（原因：{exc}）"
        ) from exc


def split_frontmatter(text: str):
    """返回 frontmatter 文本块；不存在 / 未闭合返回 None。"""
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    return parts[1]


# ═══════════════════════════════════════════════════════════════
#  共享辅助：占位符判定 / Luhn 校验（降误报核心）
# ═══════════════════════════════════════════════════════════════

_PLACEHOLDER_RE = re.compile(
    r"\*{2,}|x{4,}|\.{3,}|⋯+|<\s*[^>]+>|"
    r"(示例|测试|example|占位|your[-_]|test|fake|dummy|xxxx|占位符)",
    re.I,
)
_PLACEHOLDER_NUM_RE = re.compile(r"^\d{1,3}0{4,}$|^0{6,}$|^1[3-9]0{9}$|^1234567890{2,}$")


def is_placeholder(text: str) -> bool:
    """判断一段文本/数字是否像「示例 / 测试 / 占位」而非真实泄漏。
    用于 PII / 凭据档，避免把文档里的示例值当真泄漏误杀。"""
    t = (text or "").strip()
    if not t:
        return True
    if _PLACEHOLDER_RE.search(t):
        return True
    if _PLACEHOLDER_NUM_RE.match(t):
        return True
    return False


def _luhn_ok(num: str) -> bool:
    """Luhn 校验（银行卡号真实性初筛，降误报）。"""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ═══════════════════════════════════════════════════════════════
#  门禁检查器
# ═══════════════════════════════════════════════════════════════

SEVERITY_DEDUCTIONS = {"critical": 30, "high": 15, "medium": 5, "low": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BLOCKER_SEVERITIES = {"critical", "high"}


class SkillHubGate:
    def __init__(self, target_dir: str, use_git: bool = False, platform: str = "skillhub",
                 config: dict = None, strict: bool = False):
        self.target_dir = os.path.abspath(target_dir)
        self.skill_name = os.path.basename(self.target_dir.rstrip("/\\"))
        self.issues: list[dict] = []
        self.info_hits: list[dict] = []  # INFO 级命中：默认静音，不计入 verdict
        self.spec, self.rules = self._load_spec()
        self.yaml = None  # 延迟加载，避免无谓自安装
        # --git：默认扫 git 跟踪集（等价 CI / 发布所见）；非仓库则回退全扫
        self.use_git = use_git
        # --platform：skillhub（默认，LICENSE 等是封禁 blocker）/ github（开源许可文件豁免）
        #            / clawhub / ima（各有专属口径，见 spec.platform_profiles）
        self.platform = platform
        self._git_files = self._git_tracked() if use_git else None
        # 回灌闭环（发布后审核发现写回 feedback.json）
        self.whitelist_res: list = []
        self.learned_blockers: list = []
        self.learned_warns: list = []
        self.show_info = False
        # 外部配置生效摘要（供报告展示，让「我配的东西到底生效没」可核对）
        self.config_applied: list = []
        # --config / --rules：只许更严，越权配置直接抛 ConfigError
        try:
            self.config_applied, self.config_whitelist = config_loader.apply_config(
                self.spec, self.rules, config or {}, strict=strict)
        except config_loader.ConfigError as exc:
            raise GateConfigError(str(exc)) from exc
        # 扫描期缓存，见 _read / _iter_skill_files 的说明（对抗式审查 S1：修复前
        # 600 个文件要跑 80 秒，_read 被调 56184 次、_io.open 占 49 秒）
        self._file_cache: dict = {}
        self._files_cache: list = []

    # ── 规则加载 ──

    def _load_spec(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", "rules", "skillhub-spec.json"
        )
        if not os.path.exists(path):
            return {}, []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}, []
        self.spec_meta = data
        return data.get("spec", {}), data.get("rules", [])

    # ── 通用辅助 ──

    def _add(self, category, severity, file, line, found, recommendation,
             redline=False, authority_type="platform_policy", rule_id="", clause=""):
        self.issues.append({
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "file": file,
            "line": line,
            "found": found,
            "recommendation": recommendation,
            "redline": redline,
            "authority_type": authority_type,
            "clause": clause,
        })

    def _prime_caches(self):
        """一次性把文件清单与全部文本读进内存。

        为什么需要（对抗式审查 S1）：修复前 `check_rules` 在「pattern × target × 行」
        三层循环里反复调 `_read`，135 个 pattern × 600 个文件 = 81000 次文件重开，
        cProfile 显示 `_io.open` 独占 49 秒、整轮 80 秒。门禁是发布前要等的东西，
        这个量级不可接受。

        代价：把目标目录全部文本驻留内存。skill 目录正常几 MB，可接受；
        超大目录（>5000 文件 / >100MB）已在 BUNDLE-001 里被判 BLOCKED，
        不构成「为了过门禁先吃掉内存」的路径。
        """
        self._files_cache = list(self._walk_skill_files())
        cache = self._file_cache
        for rel, ap in self._files_cache:
            try:
                with open(ap, "r", encoding="utf-8", errors="replace") as f:
                    cache[rel] = f.readlines()
            except OSError:
                cache[rel] = []

    def _read(self, *parts):
        """读文件为行列表。命中扫描期缓存，不重复开文件。

        缓存键用 target_dir 相对路径（即 `rel`）——所有调用点传的都是相对路径，
        统一在这里 join 一次；绝对路径调用点不存在，若将来有，键会不同但仍
        退化成一次真实打开，不会算错内容。
        """
        rel = "/".join(parts)
        if rel in self._file_cache:
            return self._file_cache[rel]
        path = os.path.join(self.target_dir, *parts)
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.readlines()
        except Exception:
            return []

    def _text(self, *parts):
        return "".join(self._read(*parts))

    def _git_tracked(self):
        """返回 git 跟踪的 abs 文件列表；非 git 仓库 / git 不可用返回 None。
        仅当 target_dir 自身含 .git 才用 git 集，避免 `git ls-files` 向上找到父仓库扫到无关文件。"""
        if not os.path.isdir(os.path.join(self.target_dir, ".git")):
            return None
        try:
            out = subprocess.run(
                ["git", "ls-files"], cwd=self.target_dir,
                capture_output=True, text=True, timeout=30, check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                return [os.path.join(self.target_dir, f)
                        for f in out.stdout.split("\n") if f.strip()]
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _walk_skill_files(self):
        """实际遍历磁盘，产出 (relative_path, abs_path)，剔除 .git。
        若 use_git 且仓库可用，则只扫 git 跟踪集（等价 CI / 发布所见）。"""
        if self._git_files is not None:
            for ap in self._git_files:
                if not os.path.isfile(ap):
                    continue
                rel = os.path.relpath(ap, self.target_dir).replace("\\", "/")
                yield rel, ap
            return
        for root, dirs, files in os.walk(self.target_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            for fn in files:
                ap = os.path.join(root, fn)
                rel = os.path.relpath(ap, self.target_dir).replace("\\", "/")
                yield rel, ap

    def _iter_skill_files(self):
        """产出 (relative_path, abs_path)。扫描期返回缓存副本，避免每个检查项
        都重走一次 os.walk（v2.1.0 之前有 4 处各自遍历一遍）。"""
        if not self._files_cache:
            self._prime_caches()
        return iter(self._files_cache)

    # ── 检查 1：frontmatter YAML 合法性（faithful parse）──

    def check_frontmatter_validity(self):
        skill_md = self._read("SKILL.md")
        if not skill_md:
            self._add(
                "SPEC", "critical", "SKILL.md", 1,
                "SKILL.md 不存在", "目标目录必须包含 SKILL.md。",
                redline=True, authority_type="platform_policy", rule_id="FM-001",
            )
            return
        text = "".join(skill_md)
        fm = split_frontmatter(text)
        if fm is None:
            self._add(
                "SPEC", "critical", "SKILL.md", 1,
                "frontmatter 缺失或未用 --- 正确闭合",
                "在 SKILL.md 顶部用 `---` 包裹 YAML frontmatter。",
                redline=True, authority_type="platform_policy", rule_id="FM-001",
            )
            return
        try:
            self.yaml = load_yaml_module()
        except YamlUnavailable as exc:
            self._add(
                "SPEC", "critical", "SKILL.md", 1,
                f"YAML 解析器不可用：{exc}",
                "安装 PyYAML 后重试；本门禁不会在无法 faithful 解析时放行。",
                redline=True, authority_type="platform_policy", rule_id="FM-001",
            )
            return
        try:
            data = self.yaml.safe_load(fm)
        except Exception as exc:  # noqa: BLE001
            first = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            self._add(
                "SPEC", "critical", "SKILL.md", 1,
                f"YAML 解析失败：{first}",
                "常见原因：普通标量值里出现半角「冒号+空格」。把该值加引号，"
                "或把冒号改成全角「：」。",
                redline=True, authority_type="platform_policy", rule_id="FM-001",
            )
            return
        if not isinstance(data, dict):
            self._add(
                "SPEC", "critical", "SKILL.md", 1,
                f"frontmatter 是 {type(data).__name__}，不是 mapping",
                "frontmatter 顶层必须是键值对（mapping）。",
                redline=True, authority_type="platform_policy", rule_id="FM-001",
            )
            return
        self._fm_data = data

    # ── 检查 2：frontmatter 必填字段 + 格式（CLI 硬校验）──

    def check_frontmatter_required(self):
        if not hasattr(self, "_fm_data"):
            return  # 上一步已 BLOCKER
        data = self._fm_data
        fm = self.spec.get("frontmatter", {})
        required = fm.get("required", ["slug", "version", "displayName"])
        for field in required:
            if field not in data or data.get(field) in (None, ""):
                self._add(
                    "SPEC", "critical", "SKILL.md", 1,
                    f"缺少必填字段 `{field}`（SkillHub CLI 硬校验，缺失直接拒绝）",
                    f"在 frontmatter 添加 `{field}: <值>`。",
                    redline=True, authority_type="platform_policy", rule_id="FM-002",
                )
                continue
            val = str(data[field])
            if field == "slug":
                pat = re.compile(fm.get("slug_pattern", r"^[a-z0-9]+(-[a-z0-9]+)*$"))
                lo, hi = fm.get("slug_min", 2), fm.get("slug_max", 128)
                if not pat.match(val):
                    self._add("SPEC", "critical", "SKILL.md", 1,
                              f"slug 格式非法：`{val}`（需 kebab-case）",
                              "slug 只用小写字母/数字/连字符，如 my-skill-name。",
                              redline=True, authority_type="platform_policy", rule_id="FM-002")
                elif not (lo <= len(val) <= hi):
                    self._add("SPEC", "critical", "SKILL.md", 1,
                              f"slug 长度 {len(val)} 超出 [{lo},{hi}]",
                              "调整 slug 长度到 2–128。",
                              redline=True, authority_type="platform_policy", rule_id="FM-002")
            if field == "version":
                semver = re.compile(fm.get("semver_pattern", r"^\d+\.\d+\.\d+"))
                if not semver.match(val):
                    self._add("SPEC", "critical", "SKILL.md", 1,
                              f"version 非 SemVer：`{val}`",
                              "使用 x.y.z 格式，如 1.0.0。",
                              redline=True, authority_type="platform_policy", rule_id="FM-002")
            if field == "displayName" and not val.strip():
                self._add("SPEC", "critical", "SKILL.md", 1,
                          "displayName 为空",
                          "displayName 是非空展示名（可含空格）。",
                          redline=True, authority_type="platform_policy", rule_id="FM-002")

        # 推荐字段（不阻断，仅建议）
        for field in fm.get("recommended", []):
            if field not in data or data.get(field) in (None, ""):
                self._add(
                    "SPEC", "medium", "SKILL.md", 1,
                    f"缺少推荐字段 `{field}`",
                    f"建议补充 `{field}`（列表页摘要 / 触发词来源）。",
                    authority_type="best_practice", rule_id="FM-003",
                )

    # ── 检查 3：封禁文件类型 + 超大产物 ──

    def check_forbidden_files(self):
        # ClawHub 接受任意扩展名、不挑文件类型（与 SkillHub 不同），封禁文件检查不适用
        if self.platform == "clawhub":
            return
        forbidden = set(self.spec.get("forbidden_files", []))
        globs = self.spec.get("forbidden_globs", [])
        artifact_dirs = set(self.spec.get("artifact_dirs", []))
        # github 模式：开源许可文件（LICENSE 等）是合法的，SkillHub 才封禁，故豁免
        github_allowed = set(self.spec.get("github_allowed_files", [])) if self.platform == "github" else set()
        for rel, _ap in self._iter_skill_files():
            base = os.path.basename(rel)
            top = rel.split("/")[0]
            if base in github_allowed or top in github_allowed:
                continue
            if base in forbidden or top in forbidden:
                self._add(
                    "SPEC", "critical", rel, 1,
                    f"封禁文件/目录：`{rel}`（SkillHub 正式发布会报 400 或卡死）",
                    "发布前用 `git archive HEAD` 导出干净副本，并 rm -f 该封禁项，"
                    "切勿直接 `publish .` 仓库目录。",
                    redline=True, authority_type="platform_policy", rule_id="FORB-001",
                )
                continue
            for g in globs:
                if self._fnmatch(base, g):
                    self._add(
                        "SPEC", "critical", rel, 1,
                        f"封禁类型文件：`{rel}`",
                        "清理编译/缓存产物（*.pyc 等）后再发布。",
                        redline=True, authority_type="platform_policy", rule_id="FORB-001",
                    )
                    break
            if top in artifact_dirs:
                self._add(
                    "SPEC", "medium", rel, 1,
                    f"疑似测试产物目录：`{top}/`",
                    "测试产物（allure-results/.pytest_cache/data 等）会撑大发布包致卡死；"
                    "用 git-ignored 副本或临时移走来发布。",
                    authority_type="best_practice", rule_id="FORB-002",
                )

    @staticmethod
    def _fnmatch(name, pattern):
        import fnmatch
        return fnmatch.fnmatch(name, pattern)

    # ── 检查 4：包体计数 ──

    def check_bundle_size(self):
        bundle = self.spec.get("bundle", {})
        warn_n = bundle.get("warn_file_count", 100)
        max_n = bundle.get("max_file_count", 1000)
        warn_b = bundle.get("warn_total_bytes", 10 * 1024 * 1024)
        max_b = bundle.get("max_total_bytes", 50 * 1024 * 1024)
        count = 0
        total = 0
        for _rel, ap in self._iter_skill_files():
            count += 1
            try:
                total += os.path.getsize(ap)
            except OSError:
                pass
        if count > max_n:
            self._add(
                "SPEC", "critical", "(bundle)", 1,
                f"文件数 {count} 超过上限 {max_n}（极大概率卡死发布）",
                "清理未追踪测试产物，改用 `git archive HEAD` 导出已提交树的干净副本发布。",
                redline=True, authority_type="platform_policy", rule_id="BUNDLE-001",
            )
        elif count > warn_n:
            self._add(
                "SPEC", "medium", "(bundle)", 1,
                f"文件数 {count} 偏多（警戒线 {warn_n}）",
                "确认无多余产物混入；建议用干净副本发布。",
                authority_type="best_practice", rule_id="BUNDLE-002",
            )
        human = f"{total/1024/1024:.1f}MB"
        if total > max_b:
            self._add(
                "SPEC", "high", "(bundle)", 1,
                f"包体 {human} 超过上限 {max_b//1024//1024}MB",
                "精简资源 / 外部化大文件。",
                authority_type="platform_policy", rule_id="BUNDLE-001",
            )
        elif total > warn_b:
            self._add(
                "SPEC", "low", "(bundle)", 1,
                f"包体 {human} 偏大（警戒线 {warn_b//1024//1024}MB）",
                "确认体积合理。",
                authority_type="best_practice", rule_id="BUNDLE-002",
            )

    # ── 检查 5：版本号一致性 ──

    def check_version_consistency(self):
        if not hasattr(self, "_fm_data"):
            return
        declared = str(self._fm_data.get("version", "")).strip()
        if not declared or not re.match(r"^\d+\.\d+\.\d+", declared):
            return
        locations = self.spec.get("version_locations", [])
        mismatched = []
        for loc in locations:
            if loc == "SKILL.md":
                continue
            txt = self._text(loc)
            if not txt:
                continue
            # 找 "version" : "X.Y.Z" 或 version: X.Y.Z
            m = re.search(r'version"\s*:\s*"([^"]+)"', txt) or \
                re.search(r"(?m)^version:\s*([0-9]+\.[0-9]+\.[0-9]+)", txt)
            found = m.group(1) if m else None
            if found and found.strip() != declared:
                mismatched.append(f"{loc}={found}")
        if mismatched:
            self._add(
                "SPEC", "medium", "version", 1,
                f"版本号与 SKILL.md({declared}) 不一致：{' ; '.join(mismatched)}",
                "升级前把 version 在 SKILL.md/config.json/metadata.json/CHANGELOG.md "
                "全部统一，否则 skillhub upgrade 比不出新版本。",
                authority_type="best_practice", rule_id="VER-001",
            )

    # ── 检查 6：network 声明一致性 ──

    def check_network_consistency(self):
        if not hasattr(self, "_fm_data"):
            return
        text = self._text("SKILL.md")
        declared_none = bool(re.search(r'(?m)^\s*network:\s*none', text))
        if not declared_none:
            return
        script_dir = os.path.join(self.target_dir, "scripts")
        if not os.path.isdir(script_dir):
            return
        has_net = False
        for f in sorted(os.listdir(script_dir)):
            if not f.endswith(".py"):
                continue
            for line in self._read("scripts", f):
                ls = line.strip()
                if ls.startswith("#") or re.match(r"^(from|import)\s", ls):
                    continue
                if re.search(r"requests\.(get|post|put|delete)\s*\(", ls, re.I):
                    has_net = True
                    break
                if re.search(r"urllib\.(request|parse)\.urlopen\s*\(", ls, re.I):
                    has_net = True
                    break
                if re.search(r"socket\.(create_connection|socket)\s*\(", ls, re.I):
                    has_net = True
                    break
            if has_net:
                break
        if has_net:
            self._add(
                "SPEC", "medium", "SKILL.md", 1,
                "声明 network: none 但 scripts 含实际网络调用",
                "如实声明 network: allowed 并说明用途，或移除网络调用；"
                "描述-行为不一致会触发审核/用户质疑。",
                authority_type="platform_policy", rule_id="NET-001",
            )

    # ── 检查 7+：规则库 pattern 扫描（CONTENT / PRIVACY / SPEC）──

    # 元语境豁免：当命中词出现在「否定 / 定义 / 清单 / 说明」语境时，
    # 通常是技能在描述规则本身（自描述），而非作出违规主张，跳过以避免误报。
    META_MARKERS = [
        "不能", "禁止", "不得", "避免", "慎用", "红线", "合规", "封禁", "检测",
        "规则", "声明", "宣言", "清单", "列表", "例如", "比如", "包括", "如：",
        "用语", "建议", "措辞", "表述", "描述", "说明", "枚举", "目录", "定义",
        "识别", "扫描", "审计", "排查", "检查", "过滤", "规避", "降级", "不提供",
        "不支持", "不指导", "不应", "拒绝", "下架", "极限词", "敏感词", "敏感",
        "而不是", "而非", "不要", "切勿", "禁止", "不得", "不可",
    ]

    def check_rules(self):
        rules = list(self.rules)
        # 回灌闭环：learned_blockers 作为额外 critical BLOCKER；learned_warns 作为额外 medium
        for rec in getattr(self, "learned_blockers", []):
            pat = rec.get("pattern", "")
            if pat:
                rules.append({
                    "id": "LEARNED-BLOCKER", "category": "CONTENT",
                    "severity": "critical", "redline": True,
                    "scan_targets": ["docs", "scripts"], "patterns": [pat],
                    "description": f"回灌新增 BLOCKER：{pat}（来源：{rec.get('reason', '')}）",
                })
        for rec in getattr(self, "learned_warns", []):
            pat = rec.get("pattern", "")
            if pat:
                rules.append({
                    "id": "LEARNED-WARN", "category": "CONTENT",
                    "severity": "medium",
                    "scan_targets": ["docs", "scripts"], "patterns": [pat],
                    "description": f"回灌新增 WARN：{pat}（来源：{rec.get('reason', '')}）",
                })
        for rule in rules:
            patterns = rule.get("patterns")
            if not patterns:
                continue
            category = rule.get("category", "CONTENT")
            severity = rule.get("severity", "medium")
            redline = rule.get("redline", False)
            authority = rule.get("authority_type", "platform_policy")
            # 每平台降级：ClawHub 不做关键词内容审核，把 SkillHub 专属红线（翻墙词族等）
            # 的 BLOCKER 降级为 WARN，避免误伤正常历史/新闻类技能
            down = rule.get("platform_downgrade", {})
            if self.platform in down:
                _ds = down[self.platform]
                severity = "medium" if _ds in ("warn",) else _ds
                redline = False
            exclude = [re.compile(e, re.I) for e in rule.get("exclude_patterns", [])]
            # 元语境豁免分两档：默认叠加全局 META_MARKERS（内容红线用）；
            # 但 agentic/MCP 类规则的攻击句式本身就是「不要 X」「无需确认」——
            # 叠加全局的「不要」「无需」会把规则自己废掉，所以这类规则显式
            # 声明 use_global_meta_markers=false，只用自己那份自描述词表。
            markers = list(rule.get("self_describing_markers", []))
            if rule.get("use_global_meta_markers", True):
                markers = self.META_MARKERS + markers
            marker_pats = [re.compile(re.escape(m), re.I) for m in markers]
            scan_targets = rule.get("scan_targets", ["docs"])
            scan_docs = "docs" in scan_targets
            scan_scripts = "scripts" in scan_targets
            scan_all = "all" in scan_targets

            targets = []
            if scan_all or scan_docs:
                targets.extend(["SKILL.md", "README.md", "package.json"])
            if scan_all or scan_scripts:
                sdir = os.path.join(self.target_dir, "scripts")
                if os.path.isdir(sdir):
                    for f in sorted(os.listdir(sdir)):
                        if f.endswith(".py"):
                            targets.append(f"scripts/{f}")

            seen = set()  # 同 (rule_id, file, line) 只报一次，避免一词多命中刷屏
            for pat_str in patterns:
                pat = re.compile(pat_str, re.IGNORECASE)
                for fname in targets:
                    for lineno, line in enumerate(self._read(fname), 1):
                        m = pat.search(line)
                        if not m:
                            continue
                        if any(ep.search(line) for ep in exclude):
                            continue
                        if any(mp.search(line) for mp in marker_pats):
                            continue
                        if self._is_rule_catalog_row(line, rule.get("id", "")):
                            continue
                        # 私有白名单：只静音「确认过的误报」，绝不哑掉真问题
                        if any(w.search(line) for w in getattr(self, "whitelist_res", [])):
                            continue
                        key = (rule.get("id", ""), fname, lineno)
                        if key in seen:
                            continue
                        seen.add(key)
                        found = line.strip()[:80]
                        clause = rule.get("clause", "")
                        rec = {
                            "rule_id": rule.get("id", ""),
                            "category": category,
                            "severity": severity,
                            "file": fname,
                            "line": lineno,
                            "found": found,
                            "recommendation": rule.get("description", "请按 SkillHub 规范修改。"),
                            "redline": redline,
                            "authority_type": authority,
                            "clause": clause,
                        }
                        if rule.get("level") == "info":
                            # INFO 级：默认静音，不计入 verdict；--show-info 才在报告展示
                            self.info_hits.append(rec)
                        else:
                            self._add(category, severity, fname, lineno, found,
                                      rule.get("description", "请按 SkillHub 规范修改。"),
                                      redline=redline, authority_type=authority,
                                      rule_id=rule.get("id", ""), clause=clause)

    # 档位词：文档里的规则表会写「BLOCKED / NEEDS_FIX」这类结论
    _CATALOG_VERDICT_RE = re.compile(
        r"\b(BLOCKED|NEEDS_FIX|PASS|CRITICAL|HIGH|MEDIUM|LOW|WARN|INFO)\b", re.I)

    def _is_rule_catalog_row(self, line: str, rule_id: str) -> bool:
        """判断这一行是不是「文档里的规则清单行」，是则跳过。

        这类行的典型形态是文档里那张检查项表：
            | MCP-PROMPT-001 | 工具描述投毒：「不要告诉用户…」 | BLOCKED |
        它命中规则不是因为作者做了坏事，而是因为文档在**描述**规则。
        没有这条豁免，任何写检查项清单的文档都会被自己的门禁拦下——
        上一版就这么在检查项表里写下协议名，把自己判成了违规。

        三个条件同时成立才豁免，口径刻意收窄：
          1. 以 `|` 开头（markdown 表格行，不是正文）
          2. 行内出现本规则自己的 ID
          3. 行内出现档位词（说明这行在讲「这规则会报什么」）
        只满足 1 或 2 不豁免——否则真违规只要排版成表格就能溜过去。
        """
        if not rule_id or not line.lstrip().startswith("|"):
            return False
        return bool(re.search(rf"\b{re.escape(rule_id)}\b", line)) and bool(
            self._CATALOG_VERDICT_RE.search(line))

    # ── 检查 8：凭据泄漏（SECRET，脱敏回显）──

    def check_credentials(self):
        """PRIVACY/critical：扫描疑似凭据泄漏。
        命中一律脱敏回显（[REDACTED_SECRET]），绝不回显原文——
        避免本门禁自己把密钥写进日志 / CI 输出（那正是要检出的问题）。"""
        text_ext = (".md", ".py", ".json", ".yml", ".yaml", ".txt", ".sh", ".html", ".rst")
        for rel, _ap in self._iter_skill_files():
            if not rel.lower().endswith(text_ext):
                continue
            for lineno, line in enumerate(self._read(rel), 1):
                for rx, why in CREDENTIAL_PATTERNS:
                    if re.search(rx, line):
                        self._add(
                            "PRIVACY", "critical", rel, lineno,
                            "[REDACTED_SECRET]",
                            f"疑似{why}泄漏——请删掉真实凭据，改用占位 / env 注入；"
                            "本门禁不回显原文以防二次泄漏。",
                            redline=True, authority_type="platform_policy",
                            rule_id="SEC-CRED-001",
                        )
                        break

    # ── 检查 9：依赖钉版（WARN）──

    def check_dep_pinning(self):
        """WARN：requirements.txt 必须钉版本（== / >= / <= / ~= / !=）。
        未钉版的依赖会在 CI/本地装到不同组合，是「依赖未钉版」类回归源。"""
        req = os.path.join(self.target_dir, "requirements.txt")
        if not os.path.isfile(req):
            return
        for i, line in enumerate(self._read("requirements.txt"), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            spec = re.split(r"[ ;]", s, maxsplit=1)[0]  # 去掉环境标记 ; 与可选依赖 []
            if not re.search(r"(==|>=|<=|~=|!=)", spec):
                self._add(
                    "SPEC", "medium", "requirements.txt", i, s,
                    "依赖未钉版——请 pin 到 ==version，避免 CI/本地组合漂移。",
                    authority_type="best_practice", rule_id="DEP-PIN-001",
                )

    # ── 检查 10：持久化篡改（SEC-PERSIST-001，critical，协议 5.1）──

    PERSIST_TARGETS = re.compile(
        r"(SOUL\.md|MEMORY\.md|IDENTITY\.md|USER\.md|\.workbuddy/MEMORY\.md)", re.I)
    PERSIST_VERB = re.compile(
        r"(写入|写回|写进|修改|编辑|更新|覆盖|追加|附加|append|write|edit|update|modify|overwrite)",
        re.I)
    PERSIST_WRITE_CALL = re.compile(
        r"(open\s*\(|\.write_text\(|write_file|\.write\s*\(|save_file|\.write\b)", re.I)
    PERSIST_META_MARKERS = [
        "保护", "安全", "不应", "不得", "禁止", "不会", "不要", "切勿",
        "防御", "防护", "检测", "防止", "避免", "不代表", "不修改", "不写入",
        "请勿", "不应该", "本门禁", "红线",
    ]

    def check_persistent_tampering(self):
        """SECURITY/critical（协议 5.1）：Skill 不得指示宿主**永久**篡改用户持久化
        文件（SOUL.md / MEMORY.md / IDENTITY.md / USER.md）。这类改写越过会话、
        持久影响宿主身份与记忆，属「篡改用户数据」红线。

        双路检测，避免误伤门禁自身的说明文案：
          (a) 文档正文（SKILL.md/README.md）里的命令式「写入/修改 X 文件」指令；
          (b) 脚本里对持久化文件的实际写调用（open(...,'w') / write_text 等）。
        防御性/自描述提及（含「不得/不修改/本门禁」等）跳过。"""
        meta_pats = [re.compile(re.escape(m), re.I) for m in self.PERSIST_META_MARKERS]
        # (a) 文档命令式指令
        for fname in ["SKILL.md", "README.md"]:
            for lineno, line in enumerate(self._read(fname), 1):
                if not self.PERSIST_TARGETS.search(line):
                    continue
                if not self.PERSIST_VERB.search(line):
                    continue
                if any(mp.search(line) for mp in meta_pats):
                    continue
                self._add(
                    "SECURITY", "critical", fname, lineno, line.strip()[:80],
                    "检测到 Skill 指示宿主「写入/修改」持久化身份或记忆文件（SOUL.md/MEMORY.md 等）。"
                    "这会越过会话永久改写用户数据，违反协议 5.1「不得篡改用户数据」红线。"
                    "除非是用户明确授权的记忆写入且已在元语境声明，否则删除该指令。",
                    redline=True, authority_type="platform_policy",
                    rule_id="SEC-PERSIST-001",
                    clause="第5.1条（不得对平台/其他Skill/用户系统实施安全风险操作，包括篡改、删除用户数据）",
                )
        # (b) 脚本实际写调用
        sdir = os.path.join(self.target_dir, "scripts")
        if os.path.isdir(sdir):
            for f in sorted(os.listdir(sdir)):
                if not f.endswith(".py"):
                    continue
                for lineno, line in enumerate(self._read("scripts", f), 1):
                    if not self.PERSIST_TARGETS.search(line):
                        continue
                    if not self.PERSIST_WRITE_CALL.search(line):
                        continue
                    if any(mp.search(line) for mp in meta_pats):
                        continue
                    self._add(
                        "SECURITY", "critical", f"scripts/{f}", lineno, line.strip()[:80],
                        "脚本对持久化身份/记忆文件（SOUL.md/MEMORY.md 等）发起了实际写调用。"
                        "这会越过会话永久改写用户数据，违反协议 5.1 红线。确认是否用户明确授权，"
                        "否则改为会话内临时状态，不落盘持久化文件。",
                        redline=True, authority_type="platform_policy",
                        rule_id="SEC-PERSIST-001",
                        clause="第5.1条（不得对平台/其他Skill/用户系统实施安全风险操作，包括篡改、删除用户数据）",
                    )

    # ── 检查 11：个人信息泄漏（PRIV-PII-001，high，协议 5.4/5.6）──

    _ID_CARD_RE = re.compile(
        r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
        r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b")
    _PHONE_RE = re.compile(r"\b1[3-9]\d{9}\b")
    _BANK_RE = re.compile(r"\b\d{15,19}\b")
    _PII_CTX_RE = re.compile(
        r"(身份证|身份證|id\s*card|手机|电话|联系|手机号|phone|mobile|tel|微信|短信|"
        r"银行卡|信用卡|bank\s*card|card|account|账号|卡号)", re.I)

    @staticmethod
    def _id_card_checksum_ok(s: str) -> bool:
        """身份证 18 位校验位（GB 11643），降误报。"""
        if len(s) != 18:
            return False
        try:
            vals = [int(c) for c in s[:17]]
        except ValueError:
            return False
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check = sum(v * w for v, w in zip(vals, weights)) % 11
        code = "10X98765432"[check]
        return code == s[17].upper()

    def check_pii_leak(self):
        """PRIVACY/high（协议 5.4/5.6）：扫描身份证 / 手机号 / 银行卡号等个人信息。
        银行卡走 Luhn 校验、身份证走校验位；命中值若为占位符（示例/测试）或处于
        元语境（自描述/防护）则跳过，避免误伤文档示例。命中一律脱敏回显。
        三类 PII 各自独立上报（同一行可能同时含多种）。"""
        text_ext = (".md", ".py", ".json", ".yml", ".yaml", ".txt", ".sh", ".html", ".rst")
        meta_pats = [re.compile(re.escape(m), re.I) for m in self.META_MARKERS]
        clause = "第5.4条（保护用户个人信息）/第5.6条（数据安全与合规）"
        for rel, _ap in self._iter_skill_files():
            if not rel.lower().endswith(text_ext):
                continue
            for lineno, line in enumerate(self._read(rel), 1):
                if any(mp.search(line) for mp in meta_pats):
                    continue
                # 身份证：严格正则 + 校验位（正则已足够特异，无需上下文）
                idcard_val = None
                m = self._ID_CARD_RE.search(line)
                if m and self._id_card_checksum_ok(m.group(0)) and not is_placeholder(m.group(0)):
                    idcard_val = m.group(0)
                    self._add(
                        "PRIVACY", "high", rel, lineno, "[REDACTED_PII] (身份证号)",
                        "疑似身份证号泄漏——请脱敏为占位符（如 <your-id>），"
                        "本门禁不回显原文。协议 5.4/5.6 要求保护用户个人信息。",
                        redline=True, authority_type="platform_policy",
                        rule_id="PRIV-PII-001", clause=clause,
                    )
                # 手机/银行卡：需上下文 + 校验，避免把订单号/时间戳当卡号
                if self._PII_CTX_RE.search(line):
                    mp = self._PHONE_RE.search(line)
                    if mp and not is_placeholder(mp.group(0)):
                        self._add(
                            "PRIVACY", "high", rel, lineno, "[REDACTED_PII] (手机号)",
                            "疑似手机号泄漏——请脱敏为占位符（如 <your-phone>），"
                            "本门禁不回显原文。协议 5.4/5.6 要求保护用户个人信息。",
                            redline=True, authority_type="platform_policy",
                            rule_id="PRIV-PII-001", clause=clause,
                        )
                    for mm in self._BANK_RE.finditer(line):
                        num = mm.group(0)
                        if num == idcard_val:
                            continue  # 跳过已被识别为身份证的 18 位数字
                        if 15 <= len(num) <= 19 and _luhn_ok(num) and not is_placeholder(num):
                            self._add(
                                "PRIVACY", "high", rel, lineno, "[REDACTED_PII] (银行卡/账号)",
                                "疑似银行卡/账号泄漏——请脱敏为占位符（如 <your-card>），"
                                "本门禁不回显原文。协议 5.4/5.6 要求保护用户个人信息。",
                                redline=True, authority_type="platform_policy",
                                rule_id="PRIV-PII-001", clause=clause,
                            )
                            break  # 一行只报一次银行卡，避免刷屏

    # ── 检查 12：开源协议合规（OSS-COPYLEFT-001 / OSS-STRIP-001，high，协议 2.3）──

    _COPYLEFT_RE = re.compile(r"\b(AGPL|LGPL|GPL[- ]?v?[23]?)\b", re.I)
    _STRIP_RE = re.compile(
        r"(re\.sub\s*\([^)]*[Cc]opyright|remove.*[Ll]icense|replace.*[Ll]icense|"
        r"strip.*[Cc]opyright|delete.*[Ll]icense|sed\s+.*[Cc]opyright|"
        r"正则.*版权|清除.*版权|去除.*版权)", re.I)
    _OSS_META_MARKERS = [
        "不含", "避免", "非 GPL", "不是 GPL", "未使用", "不涉及", "不依赖",
        "不适用", "不采用", "改为", "替换", "permissive",
    ]

    def check_license_compliance(self):
        """SPEC/high（协议 2.3）：开源协议合规——
        (a) 不得违规使用传染性协议（GPL/AGPL/LGPL）污染本 Skill 分发；
        (b) 不得剥离/删除第三方代码的版权与许可声明。

        只扫文档（SKILL.md/README/LICENSE），不扫 scripts——避免把门禁自身的
        检测正则字面量（如 "GPL"/"版权"）误判为违规。"""
        targets = ["SKILL.md", "README.md", "LICENSE"]
        meta_pats = [re.compile(re.escape(m), re.I) for m in self._OSS_META_MARKERS]
        for fname in targets:
            for lineno, line in enumerate(self._read(fname), 1):
                m = self._COPYLEFT_RE.search(line)
                if m and not any(p.search(line) for p in meta_pats):
                    self._add(
                        "SPEC", "high", fname, lineno, line.strip()[:80],
                        f"提及传染性开源协议 {m.group(0)}。若本 Skill 分发/打包了此类协议代码，"
                        "会触发协议 2.3 的传染性义务（需开源衍生作品）。"
                        "请确认合规，或替换为 permissive 许可组件（MIT/Apache-2.0 等）。",
                        redline=True, authority_type="platform_policy",
                        rule_id="OSS-COPYLEFT-001",
                        clause="第2.3条（开源协议合规：保留许可声明、不违规使用传染性协议）",
                    )
                if self._STRIP_RE.search(line):
                    self._add(
                        "SPEC", "high", fname, lineno, line.strip()[:80],
                        "检测到可能剥离/删除第三方版权或许可声明的代码。协议 2.3 要求保留第三方"
                        "许可声明，不得剥离版权信息。确认该操作仅作用于自有产物，不含第三方代码。",
                        redline=True, authority_type="platform_policy",
                        rule_id="OSS-STRIP-001",
                        clause="第2.3条（开源协议合规：不得剥离版权与许可信息）",
                    )

    # ── 检查 13：ClawHub 发布前补充（LICENSE-FIELD / META-MISMATCH）──

    def check_clawhub_compliance(self):
        """仅 --platform clawhub 时运行。ClawHub 与 SkillHub 审核轴不同：
        (a) ClawHub 强制 MIT-0 且不要求在 SKILL.md 写 license 字段；写了非 MIT-0 值
            会审核打回（BLOCKER），写 MIT-0 也建议移除（WARN）。
        (b) ClawHub 校验「声明-内容一致性」：脚本调用外部 CLI / 子进程 / 网络但
            frontmatter 未声明 requires → WARN（安全扫描阶段可能打回）。"""
        if self.platform != "clawhub":
            return
        if not hasattr(self, "_fm_data"):
            return
        data = self._fm_data
        clause = "ClawHub 发布规范（强制 MIT-0 / 声明-内容一致性）"

        # (a) license 字段
        if "license" in data:
            val = str(data.get("license")).strip()
            if val.lower() == "mit-0":
                self._add(
                    "SPEC", "medium", "SKILL.md", 1,
                    f"frontmatter 声明 license: {val}（ClawHub 无需此字段）",
                    "ClawHub 强制 MIT-0 且不要求在 SKILL.md 写 license 字段；"
                    "建议移除该字段，避免与平台默认授权语义冲突。",
                    redline=False, authority_type="platform_policy",
                    rule_id="LICENSE-FIELD-001", clause=clause,
                )
            else:
                self._add(
                    "SPEC", "critical", "SKILL.md", 1,
                    f"frontmatter 声明 license: {val}（ClawHub 仅接受 MIT-0）",
                    "ClawHub 强制 MIT-0 授权，非 MIT-0 会在安全/合规审核打回。"
                    "移除 license 字段（平台默认 MIT-0），或确认已获特殊授权。",
                    redline=True, authority_type="platform_policy",
                    rule_id="LICENSE-FIELD-001", clause=clause,
                )

        # (b) requires 声明-内容一致性
        if "requires" not in data:
            sdir = os.path.join(self.target_dir, "scripts")
            if os.path.isdir(sdir):
                ext_pat = re.compile(
                    r"(subprocess\.[A-Za-z]+\(|os\.system\(|shutil\.rmtree\(|"
                    r"requests\.(get|post|put|delete)\(|"
                    r"urllib\.(request|parse)\.urlopen\(|"
                    r"socket\.(create_connection|socket)\(|"
                    r"import\s+(?:subprocess|requests|urllib|socket)\b)", re.I)
                hit_file = None
                for f in sorted(os.listdir(sdir)):
                    if not f.endswith(".py"):
                        continue
                    for line in self._read("scripts", f):
                        if ext_pat.search(line):
                            hit_file = f
                            break
                    if hit_file:
                        break
                if hit_file:
                    self._add(
                        "SPEC", "medium", "SKILL.md", 1,
                        "脚本含外部 CLI/子进程/网络调用，但 frontmatter 未声明 requires",
                        "ClawHub 审核校验「声明-内容一致性」：若 skill 依赖外部命令/子进程/网络，"
                        "请在 frontmatter 添加 requires（如 requires: [\"python3\",\"requests\"]），"
                        f"否则可能在安全扫描阶段被打回。命中文件：{hit_file}",
                        redline=False, authority_type="platform_policy",
                        rule_id="META-MISMATCH-001", clause=clause,
                    )

    # ── 检查 14：stdlib ast 危险调用薄兜底（C1′）──

    def check_ast_dangerous_calls(self):
        """SECURITY：eval/exec/os.system/shell=True/pickle 等危险调用的精确行号。

        为什么要 ast 而不是正则：正则分不清「调用」与「注释/字符串」，也给不出
        行号；而这一层只做最常见的危险调用兜底，通用漏洞挖掘交给外部深度扫描器
        （--deep-scan / --sarif-in），不在这里重造。
        """
        result = ast_guard.scan_skill(self.target_dir)
        for f in result["findings"]:
            # 把 ast_guard 给的 why（「为什么危险」）并进 clause——安全类报告里
            # 「怎么改」和「为什么危险」缺一不可，只带 recommendation 会丢掉后者
            self._add(
                "SECURITY", f["severity"], f["file"], f["line"], f["found"],
                f["recommendation"],
                redline=False, authority_type="static_analysis",
                rule_id=f["rule_id"],
                clause=f"代码安全：{f.get('why', '危险动态执行调用')}",
            )
        for note in result["notes"]:
            # 解析失败不是发布阻断项，但它意味着「这块没被扫到」——必须让人知道
            self.info_hits.append({
                "rule_id": "AST-PARSE-001", "category": "SECURITY", "severity": "info",
                "file": note["file"], "line": note["line"], "found": note["text"],
                "recommendation": "该文件未被 ast 兜底覆盖（解析失败），请人工确认其安全性。",
                "redline": False, "authority_type": "static_analysis", "clause": "",
            })

    # ── 检查 15：ima 包规范（仅 --platform ima）──

    def check_ima_compliance(self):
        """仅 --platform ima 时运行。ima 包口径与 SkillHub 不同的四件事：
        (a) frontmatter 七字段齐全；(b) 包内不得含 _meta.json（由平台生成）；
        (c) 字符串只用 ASCII 直引号（全角引号会被解析成字面量）；
        (d) 文件名纯 ASCII + trigger_keywords ≤5 条。"""
        if self.platform != "ima":
            return
        # platform_profiles 在 spec 子树里（与 frontmatter/bundle 同级）。
        # 审计 B8：它曾被放在 JSON 顶层，而 _load_spec() 只返回 spec 子树，
        # 于是这里恒为 None、ima 检查静默全跳过——不报错，只是没检查。
        profile = self.spec.get("platform_profiles", {}).get("ima")
        if not profile:
            return
        clause = f"ima 包规范（{profile.get('display_name', 'ima')}）"

        # (a) 七字段
        if hasattr(self, "_fm_data"):
            for field in profile.get("frontmatter_required", []):
                if self._fm_data.get(field) in (None, "", []):
                    self._add(
                        "SPEC", "critical", "SKILL.md", 1,
                        f"缺少 ima 必填字段 `{field}`",
                        f"在 frontmatter 添加 `{field}: <值>`。",
                        redline=True, authority_type="platform_policy",
                        rule_id="IMA-FM-001", clause=clause,
                    )
            # (d) 触发词条数
            limit = profile.get("max_trigger_keywords", 5)
            for key in ("trigger_keywords", "triggers", "use_when"):
                val = self._fm_data.get(key)
                if isinstance(val, list) and len(val) > limit:
                    self._add(
                        "SPEC", "medium", "SKILL.md", 1,
                        f"`{key}` 有 {len(val)} 条，超过 ima 上限 {limit} 条",
                        f"精简到 {limit} 条以内，只留最能区分意图的触发词。",
                        authority_type="platform_policy",
                        rule_id="IMA-TRIGGER-001", clause=clause,
                    )

        # 文件清单只取一次：_iter_skill_files() 是 os.walk 生成器，
        # 放在外层循环里会每次重建，复杂度变成 O(禁用项数 × 全目录文件数)。
        # 下面的 (b)(c)(d) 三段共用这一份清单。
        all_files = list(self._iter_skill_files())

        # (b) 平台生成物不得留在包内
        banned = set(profile.get("forbidden_files", []))
        for rel, _ap in all_files:
            if os.path.basename(rel) in banned:
                self._add(
                    "SPEC", "critical", rel, 1,
                    f"包内含平台生成物 `{os.path.basename(rel)}`",
                    f"`{os.path.basename(rel)}` 由 ima 平台自行生成，留在包里会被判结构异常。",
                    redline=True, authority_type="platform_policy",
                    rule_id="IMA-FILE-001", clause=clause,
                )

        # (c)(d) ASCII 引号 + 纯 ASCII 文件名
        for rel, _ap in all_files:
            if profile.get("ascii_filename_only") and not rel.isascii():
                self._add(
                    "SPEC", "medium", rel, 1,
                    f"文件名含非 ASCII 字符：`{rel}`",
                    "ima 要求文件名纯 ASCII（跨平台与 URL 安全），重命名为英文。",
                    authority_type="platform_policy",
                    rule_id="IMA-NAME-001", clause=clause,
                )
            if not profile.get("ascii_quotes_only"):
                continue
            for lineno, line in enumerate(self._read(rel), 1):
                bad = re.findall(r"[“”‘’]", line)
                if bad:
                    self._add(
                        "SPEC", "medium", rel, lineno, line.strip()[:80],
                        f"含全角引号 {' '.join(sorted(set(bad)))}（ima 只接受 ASCII 直引号）",
                        "把 “ ” ‘ ’ 换成 \" ' ——全角引号在部分解析器里会被当字面量。",
                        authority_type="platform_policy",
                        rule_id="IMA-QUOTE-001", clause=clause,
                    )

    # ── 运行全部 ──

    def run_all(self, show_info=False):
        # 扫描前一次性填充缓存：文件清单 + 全部文本。放在最前面是因为
        # check_frontmatter_validity 之后的每个检查项都要读文件。
        self._prime_caches()
        # 回灌闭环：加载 feedback.json（白名单静音 + learned 规则）
        fb = load_feedback()
        self.whitelist_res = _feedback_res(fb, "whitelist")
        self.learned_blockers = [r for r in (fb.get("learned_blockers") or [])
                                 if r.get("pattern")]
        self.learned_warns = [r for r in (fb.get("learned_warns") or [])
                               if r.get("pattern")]
        self.show_info = show_info
        self.check_frontmatter_validity()
        self.check_frontmatter_required()
        self.check_forbidden_files()
        self.check_bundle_size()
        self.check_version_consistency()
        self.check_network_consistency()
        self.check_rules()
        self.check_credentials()
        self.check_dep_pinning()
        self.check_persistent_tampering()
        self.check_pii_leak()
        self.check_license_compliance()
        self.check_clawhub_compliance()
        self.check_ast_dangerous_calls()
        self.check_ima_compliance()

    # ── 缝接层：L2 结果并入（v1.5.0）──

    def merge_external(self, issues: list) -> dict:
        """把外部扫描器的 issue 并入本门禁判定，返回统计摘要。

        顺序即优先级：本门禁自己的结论在前，dedupe 时保留先到的。
        L2 结果已在 sarif_io.from_sarif 里降过一级，这里不再二次降级。
        """
        before = len(self.issues)
        self.issues.extend(issues)
        kept, dropped = sarif_io.dedupe(self.issues)
        self.issues = kept
        return {"added": len(issues), "before": before,
                "after": len(self.issues), "deduped": len(dropped)}

    def suppress_baseline(self, path: str) -> int:
        """套用基线文件：命中项降为 info，返回被抑制条数。

        刻意不叫 apply_baseline：sarif_io 里已有一个 apply_baseline(issues, baseline)
        返回拆分结果，同名不同签名会让 IDE 补全把两者混起来（clean code 审计 B1）。
        「读文件」这步在这里，「怎么拆」在模块里。
        """
        baseline = sarif_io.load_baseline(path)
        if not baseline:
            return 0
        self.issues, suppressed = sarif_io.apply_baseline(self.issues, baseline)
        self.info_hits.extend(suppressed)
        return len(suppressed)

    def write_baseline(self, path: str) -> dict:
        """把当前 issue 的指纹写成基线。

        **只写非 blocker 项**（对抗式审查 B2）。基线的语义是「我确认过这些是误报」，
        把 critical 也写进去等于让「确认误报」这个动作变成「静音真问题」——
        实测 2 条凭据泄漏写入基线后复跑直接 PASS。
        对阻断项来说，「先发布再修」不是正确用法：门禁报了就该修或走 --learn whitelist
        单条豁免（那会留下理由与时间戳，可追溯）。

        返回 {"written": n, "skipped_blockers": m, "verdict": v} 供调用方回显。
        """
        blockable = [i for i in self.issues if i["severity"] in BLOCKER_SEVERITIES]
        suppressible = [i for i in self.issues if i["severity"] not in BLOCKER_SEVERITIES]
        written = sarif_io.save_baseline(
            path, suppressible, self.verdict()["verdict"], skipped=len(blockable))
        return {"written": written, "skipped_blockers": len(blockable),
                "verdict": self.verdict()["verdict"]}

    # ── 判定 ──

    def verdict(self) -> dict:
        blockers = [i for i in self.issues if i["severity"] in BLOCKER_SEVERITIES]
        warnings = [i for i in self.issues if i["severity"] not in BLOCKER_SEVERITIES]
        redlines = sum(1 for i in self.issues if i.get("redline"))
        if blockers:
            v = "BLOCKED"
            code = 1
        elif warnings:
            v = "NEEDS_FIX"
            code = 2
        else:
            v = "PASS"
            code = 0
        return {
            "verdict": v,
            "exit_code": code,
            "total": len(self.issues),
            "blockers": len(blockers),
            "warnings": len(warnings),
            "redlines": redlines,
            "critical": sum(1 for i in self.issues if i["severity"] == "critical"),
            "high": sum(1 for i in self.issues if i["severity"] == "high"),
            "medium": sum(1 for i in self.issues if i["severity"] == "medium"),
            "low": sum(1 for i in self.issues if i["severity"] == "low"),
        }

    # ── 报告 ──

    def report(self, fmt="text", output_path=None) -> str:
        v = self.verdict()
        if fmt == "json":
            result = {
                "skill": self.skill_name,
                "directory": self.target_dir,
                "platform": self.platform,
                "spec_version": getattr(self, "spec_meta", {}).get("version", ""),
                "config_applied": self.config_applied,
                "disclaimer": GATE_DISCLAIMER,
                "verdict": v,
                "issues": self.issues,
                "info_hits": self.info_hits,
            }
            txt = json.dumps(result, indent=2, ensure_ascii=False)
        elif fmt == "sarif":
            # SARIF 自带严重度与位置，不走 text 渲染；disclaimer 放 properties 里
            doc = sarif_io.to_sarif(
                self.issues,
                tool_version=GATE_VERSION,
                spec_version=getattr(self, "spec_meta", {}).get("version", ""),
            )
            doc["runs"][0]["properties"]["disclaimer"] = GATE_DISCLAIMER
            doc["runs"][0]["properties"]["platform"] = self.platform
            txt = json.dumps(doc, indent=2, ensure_ascii=False)
        else:
            lines = []
            lines.append(f"╔══ Skill 发布门禁 ══ {self.skill_name}")
            lines.append(f"║ 目录：{self.target_dir}")
            lines.append(f"║ 平台：{self.platform}")
            icon = {"PASS": "✅", "NEEDS_FIX": "⚠️", "BLOCKED": "🛑"}[v["verdict"]]
            lines.append(f"║ 结论：{icon} {v['verdict']}  "
                         f"(blockers={v['blockers']}, warnings={v['warnings']}, "
                         f"redlines={v['redlines']})")
            lines.append(f"║ 问题：critical={v['critical']} high={v['high']} "
                         f"medium={v['medium']} low={v['low']}")
            if self.config_applied:
                lines.append(f"║ 外部配置生效 {len(self.config_applied)} 项："
                             f"{'; '.join(self.config_applied)}")
            if v["verdict"] == "BLOCKED":
                lines.append("║ → 必须修复 blocker 后才能发布，否则被平台拒绝/下架。")
            elif v["verdict"] == "NEEDS_FIX":
                lines.append("║ → 仅有建议项，建议修复后发布。")
            lines.append("╠══ 问题列表 ══")
            if not self.issues:
                lines.append("║  未发现规范问题 ✓")
            else:
                for i, issue in enumerate(sorted(
                    self.issues, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)
                ), 1):
                    flag = " 🛑" if issue.get("redline") else ""
                    src = " [L2]" if issue.get("source") == "l2" else ""
                    lines.append(
                        f"║ [{issue['severity'].upper():>8}] ({issue['category']}) "
                        f"{issue['file']}:{issue['line']}{flag}{src}"
                    )
                    lines.append(f"║   → {issue['found']}")
                    lines.append(f"║   建议：{issue['recommendation']}")
                    if issue.get("clause"):
                        lines.append(f"║   依据：{issue['clause']}")
                    if i < len(self.issues):
                        lines.append("║  ──────────────────────")
            if self.info_hits and self.show_info:
                lines.append("╠══ ℹ️ INFO 级（默认静音，人工确认定位）══")
                for h in self.info_hits:
                    lines.append(f"║ [INFO] ({h['category']}) {h['file']}:{h['line']}")
                    lines.append(f"║   → {h['found']}")
                    lines.append(f"║   建议：{h['recommendation']}")
            lines.append("╚" + "═" * 50)
            lines.append("")
            lines.append(GATE_DISCLAIMER)
            txt = "\n".join(lines)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(txt)
            print(f"报告已写入: {output_path}")
        return txt


# ═══════════════════════════════════════════════════════════════
#  凭据特征（SECRET 检查用，命中脱敏回显）
# ═══════════════════════════════════════════════════════════════

# 命名刻意不含 secret 字样（避免静态分析把本列表当敏感数据来源误报）。
CREDENTIAL_PATTERNS = [
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub Token"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI 风格 API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "GitLab PAT"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack Token"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"ya29\.[0-9A-Za-z_-]{20,}", "Google OAuth Token"),
    # ── 协议 5.1 / 5.4 扩容：钱包私钥 / SSH 凭证 / 连接串 / 高熵赋值 ──
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----",
     "私钥块（RSA/EC/OpenSSH 等）"),
    (r"(?:private[ _-]?key|私钥|助记词|mnemonic|seed[ _-]?phrase)\b[\s:=]{0,4}[\"']?[0-9a-fA-F]{64}[\"']?",
     "EVM 风格 64 位十六进制私钥/助记词"),
    (r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|ftp)://[^\s:@/]+:[^\s:@/]+@",
     "数据库/FTP 连接串（含明文密码）"),
    (r"(?:api[_-]?key|apikey|access[_-]?token|secret|client[_-]?secret|token|passwd|password|pwd)\s*[=:]\s*[\"'][A-Za-z0-9_\-+/]{24,}[\"']",
     "高熵凭据明文赋值（api_key/secret/password 等）"),
]


# ═══════════════════════════════════════════════════════════════
#  回灌闭环：rules/feedback.json（随门禁走，可 git 跟踪；
#  只静音「确认过的误报」，绝不哑掉真问题）
# ═══════════════════════════════════════════════════════════════

FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "feedback.json")


def load_feedback():
    try:
        with open(FEEDBACK_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"whitelist": [], "learned_blockers": [], "learned_warns": []}


def save_feedback(data):
    # 末尾补换行：POSIX 文本文件惯例，也让 git diff 不再报 "No newline at end of file"
    with open(FEEDBACK_PATH, "w", encoding="utf-8", newline="") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def learn(entry):
    """把一次发布后审核发现回灌进规则集。
    entry: {"type": "blocker"|"whitelist"|"warn", "pattern": "...", "reason": "..."}
    返回写入后的摘要文本。"""
    if not isinstance(entry, dict) or "pattern" not in entry:
        raise ValueError('learn 需要 {"type":..., "pattern":...}')
    kind = entry.get("type")
    if kind not in ("blocker", "whitelist", "warn"):
        raise ValueError("type 必须是 blocker / whitelist / warn")
    fb = load_feedback()
    fb.setdefault("whitelist", [])
    fb.setdefault("learned_blockers", [])
    fb.setdefault("learned_warns", [])
    record = {
        "pattern": entry["pattern"], "reason": entry.get("reason", ""),
        "added": datetime.now().isoformat(timespec="seconds"),
    }
    if kind == "whitelist":
        fb["whitelist"].append(record)
    elif kind == "blocker":
        fb["learned_blockers"].append(record)
    else:
        fb["learned_warns"].append(record)
    save_feedback(fb)
    n_w = len(fb["whitelist"])
    n_b = len(fb["learned_blockers"])
    n_w2 = len(fb["learned_warns"])
    return f"已回灌 {kind}：{entry['pattern']}（whitelist={n_w}, learned_blockers={n_b}, learned_warns={n_w2}）"


def _feedback_res(fb, key):
    """把 feedback 列表里的 pattern 编译为正则；非正则按字面子串匹配。"""
    out = []
    for item in fb.get(key, []) or []:
        pat = item.get("pattern", "")
        if not pat:
            continue
        try:
            out.append(re.compile(pat, re.I))
        except re.error:
            out.append(re.compile(re.escape(pat), re.I))
    return out


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

def _strip_quotes(token: str) -> str:
    """去掉 shlex(posix=False) 保留下来的一层引号。

    只剥一层、且必须首尾配对，否则 "it's" 这种词会被削成 't'——这正是
    posix=False 换来「引号内空格不被拆」时必须自己还回去的部分。
    """
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def run_deep_scan(command: str, target_dir: str, timeout: int = 600) -> dict:
    """执行外部深度扫描器并解析其 SARIF 输出。

    三条硬约束（v3 风险表）：
    1. **不经 shell**：用 shlex.split 拆词后 list 传参，命令串里的 `;` `&&` 只会被
       当普通参数，不会被 shell 解释——这是「仅白名单形式调用」的落点。
    2. **失败不影响 L0**：非零退出 / 超时 / 输出不可解析，一律返回空结果 + note，
       由调用方记为 INFO。深度扫描器挂掉不该让发布门禁变红。
    3. **--offline 直接拒绝**：见 cmd_check 的互斥检查。

    返回 {"issues": [...], "notes": [...]}；notes 是给人看的执行日志。"""
    result = {"issues": [], "notes": []}
    # Windows 上必须先把反斜杠转成正斜杠再拆词：shlex 默认按 POSIX 语义把
    # `\` 当转义符，于是形如 "C:" + 反斜杠 + "Users" + 反斜杠 + "x.py" 的路径
    # 会被吃成一串没有分隔符的乱码（实测踩过：--deep-scan 静默不生效）。
    # Windows 的 CreateProcess 接受正斜杠路径，所以这样换是安全的。
    raw = command.replace("\\", "/") if os.name == "nt" else command
    try:
        # posix=False：保留引号原样，让 shlex 按 Windows 习惯把 "C:/Program Files/x.exe"
        # 整体当一个词。默认 posix=True 会把引号吃掉，再遇上路径里的空格就拆成两个词——
        # 路径含空格时静默失效（实测踩过：AppData\Local\Temp 这类路径必中）。
        argv = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError as exc:
        result["notes"].append(f"--deep-scan 命令无法解析：{exc}")
        return result
    argv = [_strip_quotes(a) for a in argv]
    if not argv:
        result["notes"].append("--deep-scan 为空命令，已跳过")
        return result
    argv = [a.replace("{dir}", target_dir) for a in argv]
    if "{dir}" in " ".join(argv):
        result["notes"].append("--deep-scan 命令需含 {dir} 占位符（被替换为目标目录）")
        return result
    try:
        proc = subprocess.run(argv, cwd=target_dir, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        result["notes"].append(f"--deep-scan 找不到可执行文件：{argv[0]}")
        return result
    except subprocess.TimeoutExpired:
        result["notes"].append(f"--deep-scan 超时（>{timeout}s）已中止")
        return result
    except OSError as exc:
        result["notes"].append(f"--deep-scan 执行失败：{exc}")
        return result
    if proc.returncode != 0:
        result["notes"].append(
            f"--deep-scan 退出码 {proc.returncode}，其结果未纳入判定"
            f"（stderr: {(proc.stderr or '').strip()[:120]}）")
    stdout = (proc.stdout or "").strip()
    if not stdout:
        result["notes"].append("--deep-scan 无 stdout 输出，无 SARIF 可导入")
        return result
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as exc:
        result["notes"].append(f"--deep-scan 输出不是合法 JSON（{exc}），已忽略")
        return result
    result["issues"] = sarif_io.from_sarif(doc, trusted=False, source="l2")
    result["notes"].append(f"--deep-scan 导入 {len(result['issues'])} 条 finding（已降一级）")
    return result


def load_external_sarif(path: str, trusted: bool) -> list:
    """读一份外部 SARIF 文件并转成 gate issue。文件坏掉时返回空并说明原因，
    绝不抛异常——外部工具的输出问题不该让门禁崩。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateConfigError(f"--sarif-in 读取失败：{path}（{exc}）") from exc
    if not sarif_io.looks_like_sarif(doc):
        raise GateConfigError(
            f"--sarif-in 文件不是 SARIF 2.1.0（缺 version/runs）：{path}")
    return sarif_io.from_sarif(doc, trusted=trusted, source="l2")


def cmd_check(args):
    # 回灌模式：写完即退出（不扫描）
    if args.learn is not None:
        try:
            entry = json.loads(args.learn)
        except json.JSONDecodeError as exc:
            print(f"❌ --learn JSON 解析失败：{exc}")
            sys.exit(2)
        try:
            print("🔁 " + learn(entry))
        except ValueError as exc:
            print(f"❌ {exc}")
            sys.exit(2)
        sys.exit(0)

    config = config_loader.load_config(args.config) if args.config else {}
    platform = args.platform or config.get("platform") or "skillhub"

    if args.offline and args.deep_scan:
        print("❌ --offline 与 --deep-scan 互斥：离线模式下禁止执行外部命令"
              "（这是防源码外传的硬开关，不是建议）")
        sys.exit(2)

    try:
        gate = SkillHubGate(
            args.dir, use_git=not args.all_files, platform=platform,
            config=config, strict=args.strict,
        )
    except GateConfigError as exc:
        print(f"❌ 配置错误：{exc}")
        sys.exit(2)

    # 外部白名单（--config whitelist_append）并入回灌白名单
    for pattern in getattr(gate, "config_whitelist", []):
        gate.whitelist_res.append(re.compile(pattern, re.I))

    gate.run_all(show_info=args.show_info)

    # ── 缝接层：L2 结果并入（每一步失败都不影响 L0 判定）──
    notes = []
    if args.sarif_in:
        try:
            l2 = load_external_sarif(args.sarif_in, trusted=args.sarif_trusted)
        except GateConfigError as exc:
            # 走 stderr：stdout 要留给报告本体，json/sarif 得能被 `| jq` 直接消费
            print(f"⚠️ {exc}（已忽略，不影响 L0 判定）", file=sys.stderr)
            l2 = []
        if l2:
            stats = gate.merge_external(l2)
            notes.append(f"SARIF 导入 {stats['added']} 条（去重 {stats['deduped']} 条）")
    if args.deep_scan:
        deep = run_deep_scan(args.deep_scan, gate.target_dir)
        if deep["issues"]:
            gate.merge_external(deep["issues"])
        notes += deep["notes"]
    if args.baseline and args.write_baseline:
        # 这两个参数同开会「读进来再写回去」，实测把基线清空（对抗式审查 B3）：
        # write 的是 suppress 之后的列表，被抑制的项已经不在里面了。
        # 语义上这俩也不该共存于一次调用——读基线是「用它筛」，写基线是「重新定义它」。
        print("❌ --baseline 与 --write-baseline 不能同开："
              "先抑制再写入会把基线清空（写进去的是已过滤后的列表）。"
              "请分两次跑。", file=sys.stderr)
        sys.exit(2)

    if args.baseline:
        n = gate.suppress_baseline(args.baseline)
        notes.append(f"基线抑制 {n} 条" if n else "基线为空或无命中")

    if args.write_baseline:
        result = gate.write_baseline(args.write_baseline)
        notes.append(f"已写入基线 {result['written']} 条指纹 → {args.write_baseline}")
        if result["skipped_blockers"]:
            notes.append(
                f"已跳过 {result['skipped_blockers']} 条 blocker（critical/high 不入基线）。"
                "阻断项请修掉，或用 --learn whitelist 单条豁免以留下可追溯记录。")

    out = gate.report(fmt=args.format, output_path=args.output)
    if notes and args.format == "text":
        print("── 缝接层 ──")
        for n in notes:
            print(f"  · {n}")
    elif notes:
        # json/sarif 消费方要能直接 pipe，缝接层日志改走 stderr
        for n in notes:
            print(f"· {n}", file=sys.stderr)
    print(out)
    sys.exit(gate.verdict()["exit_code"])


def cmd_dirs(args):
    base = args.dir
    dirs = args.dirs or []
    if not dirs:
        base = base or os.path.dirname(os.path.abspath("."))
        for entry in sorted(os.listdir(base)):
            sd = os.path.join(base, entry)
            if os.path.isdir(sd) and os.path.isfile(os.path.join(sd, "SKILL.md")):
                dirs.append(sd)
    rows = []
    for d in dirs:
        g = SkillHubGate(d, platform=args.platform)
        g.run_all()
        v = g.verdict()
        rows.append((g.skill_name, v))
    rows.sort(key=lambda r: (r[1]["exit_code"], -r[1]["blockers"]))
    print(f"{'Skill':<30} {'结论':>10} {'blk':>4} {'warn':>4} {'red':>4}")
    print("-" * 56)
    for name, v in rows:
        print(f"{name:<30} {v['verdict']:>10} {v['blockers']:>4} "
              f"{v['warnings']:>4} {v['redlines']:>4}")
    worst = rows[-1] if rows else None
    if worst and worst[1]["verdict"] != "PASS":
        print(f"\n⚠ 最低分：{worst[0]} ({worst[1]['verdict']}) — 修复后再发布。")
    sys.exit(0 if all(r[1]["verdict"] == "PASS" for r in rows) else 1)


def main():
    parser = argparse.ArgumentParser(
        description="Skill 发布门禁（代码安全 + 平台规范）— skill-publish-gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 gate.py check --dir ./my-skill\n"
            "  python3 gate.py check --dir ./my-skill --json\n"
            "  python3 gate.py check --dir ./my-skill --output gate-report.txt\n"
            "  python3 gate.py check --dir ./my-skill --show-info   # 显示 INFO 级（出站代理）\n"
            "  python3 gate.py check --dir ./my-skill --all-files  # 强制全扫（不依赖 git）\n"
            "  python3 gate.py check --dir ./my-skill --platform github  # 开源副本预检（LICENSE 豁免）\n"
            "  python3 gate.py check --dir ./my-skill --platform ima     # 腾讯 ima 知识库包规范\n"
            "  python3 gate.py check --dir ./my-skill --format sarif -o gate.sarif\n"
            "  python3 gate.py check --dir ./my-skill --sarif-in domsec.sarif  # 导入外部深度结果\n"
            "  python3 gate.py check --dir ./my-skill --config ./gate.json --strict\n"
            "  python3 gate.py check --dir ./my-skill --baseline ./baseline.json\n"
            "  python3 gate.py check --dir ./my-skill --offline --deep-scan 'x {dir}'  # 会报错\n"
            "  python3 gate.py check --dir ./my-skill --learn \\\n"
            "      '{\"type\":\"blocker\",\"pattern\":\"新危险词\",\"reason\":\"平台审核打回：...\"}'\n"
            "  python3 gate.py dirs --dir ~/.workbuddy/skills\n\n"
            "退出码: 0=PASS  2=NEEDS_FIX  1=BLOCKED\n"
        ),
    )
    parser.add_argument("--disclaimer", action="store_true", help="显示免责声明")
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="对单个 skill 做门禁检查（默认）")
    p_check.add_argument("--dir", "-d", default=".", help="目标 skill 目录（默认当前目录）")
    p_check.add_argument("--format", "-f", choices=["text", "json", "sarif"], default="text",
                         help="报告格式；sarif 为 SARIF 2.1.0（喂 GitHub Code Scanning）")
    p_check.add_argument("--output", "-o", default=None, help="输出到文件")
    p_check.add_argument("--platform", "-p", default=None,
                         help="目标平台：skillhub（默认，LICENSE 等是封禁 blocker）/ github（开源许可文件豁免）"
                              "/ clawhub（接受任意扩展名，网络规避词族降级，补 MIT-0/requires 一致性检查）"
                              "/ ima（腾讯 ima 知识库包规范）。缺省时读 --config 的 platform，再默认 skillhub")
    p_check.add_argument("--show-info", action="store_true",
                         help="显示 INFO 级命中（出站代理、MCP 未声明等，默认静音，需人工确认定位）")
    p_check.add_argument("--all-files", action="store_true",
                         help="强制扫全目录（默认若目录是 git 仓库则只扫 git 跟踪集）")
    p_check.add_argument("--learn", default=None,
                         help="回灌：传入 JSON {\"type\":\"blocker|whitelist|warn\","
                              "\"pattern\":...,\"reason\":...}，写回 rules/feedback.json 后退出")
    # ── v1.5.0 缝接层 ──
    p_check.add_argument("--config", default=None,
                         help="外部配置文件（.json/.yaml）：阈值、封禁文件追加、规则追加。"
                              "只许更严：阈值只能调低、红线规则不可被覆盖（--strict 全锁）")
    p_check.add_argument("--strict", action="store_true",
                         help="锁定内置规则库：配置里的 spec/封禁文件覆盖一律报错（仅允许追加类）")
    p_check.add_argument("--sarif-in", default=None,
                         help="导入外部扫描器的 SARIF 2.1.0（domsec/SkillSpector/Codex Security），"
                              "finding 一律降一级后并入判定")
    p_check.add_argument("--sarif-trusted", action="store_true",
                         help="声明 --sarif-in 的 finding 已过验证层，不做降级（谨慎使用）")
    p_check.add_argument("--baseline", default=None,
                         help="基线文件：抑制其中列出的指纹（确认过的误报）")
    p_check.add_argument("--write-baseline", default=None,
                         help="把本次全部 issue 的指纹写入基线文件（确认误报后再用）")
    p_check.add_argument("--deep-scan", default=None,
                         help="调用外部深度扫描器并导入其 SARIF 输出，形如 "
                              "'python3 ~/tools/scanner.py --format sarif {dir}'。"
                              "{dir} 会被替换为目标目录；不经 shell；失败不影响 L0 判定。"
                              "路径含空格时必须加引号（Windows 尤其："
                              "\"C:/Program Files/x.exe\" scanner.py {dir}）")
    p_check.add_argument("--offline", action="store_true",
                         help="硬开关：禁止 --deep-scan（防 CI 配置手滑把源码传给外部服务）")
    p_check.set_defaults(func=cmd_check)

    p_dirs = sub.add_parser("dirs", help="批量检查多个 skill 并汇总")
    p_dirs.add_argument("--dir", "-d", default=".", help="含多个 skill 的父目录")
    p_dirs.add_argument("dirs", nargs="*", help="或直接指定目录列表")
    p_dirs.add_argument("--platform", "-p", default="github",
                        help="目标平台（同 check --platform；批量体检默认 github，"
                             "因为被检目录通常含 LICENSE/.gitignore 等开源仓库文件")
    p_dirs.set_defaults(func=cmd_dirs)

    args = parser.parse_args()
    if args.disclaimer:
        print(GATE_DISCLAIMER)
        sys.exit(0)
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
