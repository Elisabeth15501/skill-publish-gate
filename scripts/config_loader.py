#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部配置加载（--config / --rules）：让门禁从「我自用的脚本」长成「可复用的门禁」。

为什么需要（这是 v1.5.0 性价比最高的一条）：
  规则阈值全写死在 rules/skillhub-spec.json，CLI 参数只有 7 个。一个发布门禁
  如果连参数都不可配置，别人装上之后第一件事就是「改源码」——那就等于没有分发。
  对标物：Codex Security 的 project-configuration（YAML/JSON + editor schema）、
  domsec 的四级配置合并、SkillSpector 的 baseline。

安全边界（本模块存在的全部理由就是守住这两条）：
  1. **只许放宽，不许放宽红线**。外部配置可以追加规则、追加封禁文件、可以调低
     阈值（更严），但**不能**把 redline 规则降级、不能删规则、不能调高阈值。
     换句话说：配置能让门禁更严，不能让门禁更松。这是「发布门禁」和「配置文件」
     的本质区别——前者是守闸门的，后者不该有钥匙。
  2. **--strict 是显式锁死**。加了 --strict，任何 spec/rules 覆盖直接报错退出，
     供「发布流水线必须用仓库内规则库」的 CI 场景。

配置文件形态（YAML 与 JSON 等价，扩展名决定解析器）：
    platform: github              # 覆盖 --platform 的默认值
    spec:
      bundle: {max_file_count: 500}
      frontmatter: {required: [slug, version, displayName, name]}
    forbidden_files_append: [".env.local"]
    rules_append: [ {id: MY-001, severity: medium, patterns: ["..."], ...} ]
    whitelist_append: ["已确认的误报正则"]
"""

from __future__ import annotations

import json
import os
import re

# ═══════════════════════════════════════════════════════════════
#  字段策略：每个可覆盖字段必须归入一档，否则不许覆盖
# ═══════════════════════════════════════════════════════════════

# 为什么要这张表（对抗式审查 B1 的教训）：
#   v2.1.0 之前只有 _LOWER_IS_STRICTER 四个 bundle 字段有方向性保护，
#   `frontmatter` 段完全裸奔——一个 6 行配置 `{"spec":{"frontmatter":{"required":[],
#   "slug_pattern":".*"}}}` 就让 BLOCKED 变成 PASS。门禁的「不可绕过」是它全部价值
#   的来源，「配置只能更严」必须是**结构性保证**，不能靠作者记得住哪个字段要紧。

LOWER_ONLY = "lower_only"   # 数字越小越严：只许调小
LOCKED = "locked"           # 禁止覆盖（正则、必填清单、顶层清单——放宽即绕过门禁）

# key 是 f"{section}.{key}"；段内没列出的字段默认拒绝覆盖（fail-closed）
FIELD_POLICY = {
    # —— 包体阈值：只许调低 ——
    "bundle.max_file_count": LOWER_ONLY,
    "bundle.max_total_bytes": LOWER_ONLY,
    "bundle.warn_file_count": LOWER_ONLY,
    "bundle.warn_total_bytes": LOWER_ONLY,
    # —— 顶层列表字段（forbidden_files / forbidden_globs / version_locations /
    #    artifact_dirs / github_allowed_files）：不可用 spec 段落覆盖，只能走
    #    对应的 *_append 键（只增不减）。列在这里是为了让误用时报出准确原因。
    "forbidden_files": LOCKED,
    "forbidden_globs": LOCKED,
    "version_locations": LOCKED,
    "artifact_dirs": LOCKED,
    "github_allowed_files": LOCKED,
    # —— frontmatter 硬校验：全锁 ——
    # slug/version/displayName 缺失或格式错会被平台 CLI 直接拒绝（400），
    # 放宽它们等于让门禁对一个必然被拒的包说 PASS
    "frontmatter.required": LOCKED,
    "frontmatter.slug_pattern": LOCKED,
    "frontmatter.semver_pattern": LOCKED,
    "frontmatter.slug_min": LOCKED,
    "frontmatter.slug_max": LOCKED,
}


class ConfigError(ValueError):
    """配置非法。调用方应直接终止并原样回显——配置错误必须硬失败，
    绝不能「忽略这个字段继续跑」，否则用户以为配生效了。"""


def load_config(path: str) -> dict:
    """读配置文件。扩展名 .yml/.yaml 走 PyYAML，其余按 JSON 解析。"""
    if not os.path.isfile(path):
        raise ConfigError(f"配置文件不存在：{path}")
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if path.lower().endswith((".yml", ".yaml")):
        return _load_yaml(raw, path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON：{path}（{exc}）") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"配置文件顶层必须是对象（mapping）：{path}")
    return data


def _load_yaml(raw: str, path: str) -> dict:
    """YAML 分支。PyYAML 缺失时给出可执行的修复指引，不静默降级到 JSON 解析
    （那会把合法 YAML 报成语法错，误导用户去改文件）。"""
    try:
        import yaml  # type: ignore
    except ImportError:
        raise ConfigError(
            f"{path} 是 YAML 配置，需要 PyYAML：pip install pyyaml"
            "（或改用 .json 扩展名，本工具两种格式等价）"
        ) from None
    try:
        data = yaml.safe_load(raw)
    except Exception as exc:  # noqa: BLE001 —— PyYAML 异常类型不统一
        raise ConfigError(f"YAML 解析失败：{path}（{exc}）") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"配置文件顶层必须是对象（mapping）：{path}")
    return data


# ═══════════════════════════════════════════════════════════════
#  应用到 spec / rules（严格：只许更严）
# ═══════════════════════════════════════════════════════════════

def apply_config(spec: dict, rules: list, config: dict, strict: bool = False) -> tuple:
    """把外部配置合并进 spec / rules，就地修改。

    返回 (生效摘要列表, 白名单正则列表)。两个返回值而不是一个摘要字符串：
    白名单的**内容**要被调用方写进 feedback，摘要只给人看——让调用方从
    「spec.{section}.{key}: a → b」这类字符串里反解正则是不可能的任务。

    strict=True 时不做任何覆盖，只允许「追加」类操作——用于 CI 里锁定规则库。
    合并而非替换的原因：spec.json 里还有大量本配置没提到的字段，整体替换会
    把门禁削成半残，而「只改我写了的」是所有配置系统的基本契约。
    """
    applied = []
    whitelist = []
    if not config:
        return applied, whitelist

    if strict and _has_overrides(config):
        raise ConfigError(
            "--strict 已启用：不允许任何覆盖类配置"
            "（spec / forbidden_files_append / rules_append / whitelist_append 全部拒绝）。"
            "如需放宽，请去掉 --strict 并留下理由记录。"
        )

    applied += _apply_spec(spec, config.get("spec"))
    applied += _apply_files(spec, config.get("forbidden_files_append"))
    applied += _apply_rules(rules, config.get("rules_append"))
    whitelist += _apply_whitelist(config.get("whitelist_append"))
    return applied, whitelist


def _has_overrides(config: dict) -> bool:
    """--strict 下判断配置里是否含有「任何覆盖类」键。

    四类全算：spec / forbidden_files_append / rules_append / whitelist_append。
    v2.1.0 漏了后两类，等于「--strict 锁死规则库」却仍能用白名单静音红线
    （对抗式审查 S3）——白名单和追加规则本质都是改判据，不该被 strict 放过。
    """
    return bool(config.get("spec") or config.get("forbidden_files_append")
                or config.get("rules_append") or config.get("whitelist_append"))


def _apply_spec(spec: dict, overrides: dict) -> list:
    """逐层合并 spec 覆盖项，按 FIELD_POLICY 的三档语义逐字段裁决。

    fail-closed：字段没在 FIELD_POLICY 里登记 → 直接拒绝。宁可让用户抱怨
    「想调一个字段却被拒」，也不能因为「作者忘了登记」就静默放行。
    """
    if not overrides:
        return []
    applied = []
    for section, values in overrides.items():
        if section not in spec:
            raise ConfigError(f"spec 覆盖指向不存在的段落：{section}")
        target = spec[section]
        # spec 里有一批「顶层就是列表」的字段（forbidden_files / forbidden_globs /
        # version_locations / artifact_dirs），它们不是段落、没有子键。判断必须放在
        # 「必须是对象」之前，否则会报出与真实原因无关的错误（曾把
        # frontmatter.required 也报成「顶层列表字段」，让人以为是别的东西）。
        if isinstance(target, list):
            raise ConfigError(
                f"spec.{section} 是顶层列表字段，不能用 spec 段落覆盖——"
                f"请改用专门的追加键（如 forbidden_files_append）。"
                "追加键是只增不减的，用它无法绕过门禁。"
            )
        if not isinstance(values, dict):
            raise ConfigError(f"spec.{section} 必须是对象（mapping）")
        for key, new in values.items():
            dotted = f"{section}.{key}"
            if key not in target:
                raise ConfigError(f"spec.{dotted} 没有可覆盖的字段（段落 {section} 里不存在）")
            policy = FIELD_POLICY.get(dotted)
            if policy is None:
                raise ConfigError(
                    f"spec.{dotted} 未登记覆盖策略，拒绝覆盖。"
                    "字段必须先在 config_loader.FIELD_POLICY 里显式登记为 "
                    "lower_only / locked 之一——"
                    "未登记即拒绝是刻意的 fail-closed，防止漏登记变成绕过口。"
                )
            old = target[key]
            if policy == LOCKED:
                raise ConfigError(
                    f"spec.{dotted} 是受保护字段，禁止覆盖"
                    f"（当前 {old!r} → 配置给了 {new!r}）。"
                    "放宽它等于让门禁对一个必然被平台拒绝的包判 PASS。"
                )
            if policy == LOWER_ONLY and isinstance(old, (int, float)):
                if new > old:
                    raise ConfigError(
                        f"spec.{dotted} 只能调低（更严）：当前 {old}，"
                        f"配置给了 {new}。放宽阈值会让门禁变松，不允许。"
                    )
            target[key] = new
            applied.append(f"spec.{dotted}: {old} → {new}")
    return applied


def _apply_files(spec: dict, extra) -> list:
    """追加封禁文件（只增不减）。去重后写回，保证幂等。"""
    if not extra:
        return []
    if not isinstance(extra, list):
        raise ConfigError("forbidden_files_append 必须是列表")
    current = spec.setdefault("forbidden_files", [])
    added = [f for f in extra if isinstance(f, str) and f not in current]
    if added:
        current.extend(added)
    return [f"forbidden_files += {f}" for f in added]


_MAX_RULE_PATTERN_LEN = 200       # 单条 pattern 长度上限
_MAX_RULE_PATTERNS_PER_RULE = 20  # 单条规则的 pattern 条数上限
_MAX_WHITELIST_ENTRIES = 20       # 白名单总条数上限（对抗式审查 S3：曾可一次塞满把门禁废掉）

# 灾难性回溯的最小特征：嵌套量词 (x+)+ / (x*)* 等。对抗式审查 S5 实测
# (a+)+b 每多 4 个字符耗时约 16 倍，22 个 a 就要 0.29s，长输入直接挂死进程。
# 这里只做粗检（宁可误拒也不放行），不做完整的正则复杂度分析。
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*]\)\s*[+*]")


def _reject_risky_pattern(pattern: str, rule_id: str) -> None:
    """拒绝过长、过多、疑似灾难性回溯的外部 pattern。

    内置规则不受此限——它们是本项目维护者自己审过的；这里只管外部输入，
    因为 `--config` 可能来自别人写的文件。
    """
    if len(pattern) > _MAX_RULE_PATTERN_LEN:
        raise ConfigError(
            f"规则 {rule_id} 的 pattern 过长（{len(pattern)} > {_MAX_RULE_PATTERN_LEN}）："
            f"{pattern[:60]}…"
        )
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise ConfigError(
            f"规则 {rule_id} 的 pattern 含嵌套量词（疑似灾难性回溯 ReDoS）：{pattern}。"
            "如 `(a+)+` 会随输入长度指数级耗时，足以挂死门禁。"
            "请改写为无嵌套形式（如 `a+b`），或用等价的多条简单规则。"
        )


def _apply_rules(rules: list, extra) -> list:
    """追加自定义规则。已有 ID 视为配置错误——静默覆盖等于让配置悄悄改判据。"""
    if not extra:
        return []
    if not isinstance(extra, list):
        raise ConfigError("rules_append 必须是列表")
    existing = {r.get("id") for r in rules}
    applied = []
    for rule in extra:
        if not isinstance(rule, dict):
            raise ConfigError("rules_append 每项必须是对象（mapping）")
        rid = rule.get("id")
        if not rid:
            raise ConfigError("rules_append 每项必须有 id")
        if rid in existing:
            raise ConfigError(
                f"规则 ID 重复：{rid}。内置规则不可被外部配置覆盖——"
                "请换个 ID，或把它写进 skill 自己的 rules/ 目录。"
            )
        if not rule.get("patterns"):
            raise ConfigError(f"规则 {rid} 缺少 patterns（没有 pattern 的规则不会执行）")
        if not isinstance(rule["patterns"], list):
            raise ConfigError(f"规则 {rid} 的 patterns 必须是列表")
        if len(rule["patterns"]) > _MAX_RULE_PATTERNS_PER_RULE:
            raise ConfigError(
                f"规则 {rid} 的 pattern 有 {len(rule['patterns'])} 条，超过上限 "
                f"{_MAX_RULE_PATTERNS_PER_RULE}"
            )
        # level=info 会让规则命中后进 info_hits、永不参与 verdict。
        # 允许「声明 critical 却永不阻断」这种组合，等于给配置一把万能静音钥匙
        # （对抗式审查 S4）——info 级是内置规则用来「默认静音待人工确认」的机制，
        # 外部自定义规则没有这个正当理由，一律必须真实参与判定。
        if rule.get("level") == "info":
            raise ConfigError(
                f"规则 {rid} 不允许 level=info：info 级命中不计入 verdict，"
                "会让这条规则永不阻断。自定义规则请用 severity 表达档位。"
            )
        for pattern in rule["patterns"]:
            if not isinstance(pattern, str):
                raise ConfigError(f"规则 {rid} 的 pattern 必须是字符串")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"规则 {rid} 的 pattern 不是合法正则：{pattern}（{exc}）") from exc
            _reject_risky_pattern(pattern, rid)
        rules.append(rule)
        existing.add(rid)
        applied.append(f"rules += {rid}")
    return applied


def _apply_whitelist(extra) -> list:
    """校验并返回白名单正则（内容而非摘要——调用方要拿它去实际静音匹配）。

    白名单对**所有规则**生效（含 RED-NET-* 红线），因此条目数与单条长度都要有上限：
    否则一个配置文件就能把整张红线表静音，等于持有万能钥匙。
    """
    if not extra:
        return []
    if not isinstance(extra, list):
        raise ConfigError("whitelist_append 必须是列表")
    if len(extra) > _MAX_WHITELIST_ENTRIES:
        raise ConfigError(
            f"whitelist_append 有 {len(extra)} 条，超过上限 {_MAX_WHITELIST_ENTRIES}。"
            "白名单对所有规则生效（含内容红线），大量条目等于把门禁整体静音。"
            "少量误报请用 --learn whitelist 单条回灌。"
        )
    valid = []
    for pattern in extra:
        if not isinstance(pattern, str):
            raise ConfigError("whitelist_append 每项必须是字符串正则")
        if len(pattern) > _MAX_RULE_PATTERN_LEN:
            raise ConfigError(
                f"白名单 pattern 过长（{len(pattern)} > {_MAX_RULE_PATTERN_LEN}）："
                f"{pattern[:60]}…"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"白名单 pattern 不是合法正则：{pattern}（{exc}）") from exc
        valid.append(pattern)
    return valid
