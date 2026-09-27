#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SkillHub 发布前本地门禁 — skillhub-gate
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

依赖：PyYAML（faithful YAML 解析）。
  脚本会先尝试 `import yaml`；缺失则自动 pip install 到当前解释器；
  若仍不可用，会作为 BLOCKER 报错退出，绝不静默通过。

纯 Python 标准库 + PyYAML。无网络请求（自动安装 PyYAML 除外）。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

GATE_DISCLAIMER = (
    "免责声明：本门禁仅做本地规范预检，不构成 SkillHub 审核保证。"
    "最终能否上架由 SkillHub 三线审核决定，责任由开发者自行承担。"
)


# ═══════════════════════════════════════════════════════════════
#  YAML 解析（faithful parse，带自安装兜底）
# ═══════════════════════════════════════════════════════════════

class YamlUnavailable(RuntimeError):
    pass


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
    def __init__(self, target_dir: str, use_git: bool = False, platform: str = "skillhub"):
        self.target_dir = os.path.abspath(target_dir)
        self.skill_name = os.path.basename(self.target_dir.rstrip("/\\"))
        self.issues: list[dict] = []
        self.info_hits: list[dict] = []  # INFO 级命中：默认静音，不计入 verdict
        self.spec, self.rules = self._load_spec()
        self.yaml = None  # 延迟加载，避免无谓自安装
        # --git：默认扫 git 跟踪集（等价 CI / 发布所见）；非仓库则回退全扫
        self.use_git = use_git
        # --platform：skillhub（默认，LICENSE 等是封禁 blocker）/ github（开源许可文件豁免）
        self.platform = platform
        self._git_files = self._git_tracked() if use_git else None
        # 回灌闭环（发布后审核发现写回 feedback.json）
        self.whitelist_res: list = []
        self.learned_blockers: list = []
        self.learned_warns: list = []
        self.show_info = False

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

    def _read(self, *parts):
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

    def _iter_skill_files(self):
        """产出 (relative_path, abs_path) 供扫描，剔除 .git。
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
            exclude = [re.compile(e, re.I) for e in rule.get("exclude_patterns", [])]
            markers = [m for m in self.META_MARKERS]
            markers += rule.get("self_describing_markers", [])
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

    # ── 运行全部 ──

    def run_all(self, show_info=False):
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
                "spec_version": getattr(self, "spec_meta", {}).get("version", ""),
                "disclaimer": GATE_DISCLAIMER,
                "verdict": v,
                "issues": self.issues,
                "info_hits": self.info_hits,
            }
            txt = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            lines = []
            lines.append(f"╔══ SkillHub 发布前本地门禁 ══ {self.skill_name}")
            lines.append(f"║ 目录：{self.target_dir}")
            icon = {"PASS": "✅", "NEEDS_FIX": "⚠️", "BLOCKED": "🛑"}[v["verdict"]]
            lines.append(f"║ 结论：{icon} {v['verdict']}  "
                         f"(blockers={v['blockers']}, warnings={v['warnings']}, "
                         f"redlines={v['redlines']})")
            lines.append(f"║ 问题：critical={v['critical']} high={v['high']} "
                         f"medium={v['medium']} low={v['low']}")
            if v["verdict"] == "BLOCKED":
                lines.append("║ → 必须修复 blocker 后才能 `skillhub publish`，否则被拒/下架。")
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
                    lines.append(
                        f"║ [{issue['severity'].upper():>8}] ({issue['category']}) "
                        f"{issue['file']}:{issue['line']}{flag}"
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
    with open(FEEDBACK_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


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
    # 默认 git 跟踪集（等价发布所见）；--all-files 强制全扫
    use_git = not args.all_files
    gate = SkillHubGate(args.dir, use_git=use_git, platform=args.platform)
    gate.run_all(show_info=args.show_info)
    out = gate.report(fmt=args.format, output_path=args.output)
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
        description="SkillHub 发布前本地门禁 — skillhub-gate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 gate.py check --dir ./my-skill\n"
            "  python3 gate.py check --dir ./my-skill --json\n"
            "  python3 gate.py check --dir ./my-skill --output gate-report.txt\n"
            "  python3 gate.py check --dir ./my-skill --show-info   # 显示 INFO 级（出站代理）\n"
            "  python3 gate.py check --dir ./my-skill --all-files  # 强制全扫（不依赖 git）\n"
            "  python3 gate.py check --dir ./my-skill --platform github  # 开源副本预检（LICENSE 豁免）\n"
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
    p_check.add_argument("--format", "-f", choices=["text", "json"], default="text")
    p_check.add_argument("--output", "-o", default=None, help="输出到文件")
    p_check.add_argument("--platform", "-p", choices=["skillhub", "github"], default="skillhub",
                         help="目标平台：skillhub（默认，LICENSE 等是封禁 blocker）/ github（开源许可文件豁免）")
    p_check.add_argument("--show-info", action="store_true",
                         help="显示 INFO 级命中（出站代理等，默认静音，需人工确认定位）")
    p_check.add_argument("--all-files", action="store_true",
                         help="强制扫全目录（默认若目录是 git 仓库则只扫 git 跟踪集）")
    p_check.add_argument("--learn", default=None,
                         help="回灌：传入 JSON {\"type\":\"blocker|whitelist|warn\","
                              "\"pattern\":...,\"reason\":...}，写回 rules/feedback.json 后退出")
    p_check.set_defaults(func=cmd_check)

    p_dirs = sub.add_parser("dirs", help="批量检查多个 skill 并汇总")
    p_dirs.add_argument("--dir", "-d", default=".", help="含多个 skill 的父目录")
    p_dirs.add_argument("dirs", nargs="*", help="或直接指定目录列表")
    p_dirs.add_argument("--platform", "-p", choices=["skillhub", "github"], default="skillhub",
                        help="目标平台（同 check --platform）")
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
