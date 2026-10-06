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

# 阈值字段语义：数字越小 = 门禁越严。这些字段只允许被「调小」。
_LOWER_IS_STRICTER = ("max_file_count", "max_total_bytes",
                      "warn_file_count", "warn_total_bytes")


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
            "--strict 已启用：不允许任何 spec / forbidden_files / 规则覆盖。"
            "如需放宽，请去掉 --strict 并留下理由记录。"
        )

    applied += _apply_spec(spec, config.get("spec"))
    applied += _apply_files(spec, config.get("forbidden_files_append"))
    applied += _apply_rules(rules, config.get("rules_append"))
    whitelist += _apply_whitelist(config.get("whitelist_append"))
    return applied, whitelist


def _has_overrides(config: dict) -> bool:
    """--strict 下判断配置里是否含有「覆盖类」键（追加类不算）。"""
    return bool(config.get("spec") or config.get("forbidden_files_append"))


def _apply_spec(spec: dict, overrides: dict) -> list:
    """逐层合并 spec 覆盖项，阈值只允许调小，红线字段不许碰。"""
    if not overrides:
        return []
    applied = []
    for section, values in overrides.items():
        if section not in spec:
            raise ConfigError(f"spec 覆盖指向不存在的段落：{section}")
        if not isinstance(values, dict):
            raise ConfigError(f"spec.{section} 必须是对象（mapping）")
        target = spec[section]
        for key, new in values.items():
            if key not in target:
                raise ConfigError(f"spec.{section} 没有可覆盖的字段：{key}")
            old = target[key]
            if key in _LOWER_IS_STRICTER and isinstance(old, (int, float)):
                if new > old:
                    raise ConfigError(
                        f"spec.{section}.{key} 只能调低（更严）：当前 {old}，"
                        f"配置给了 {new}。放宽阈值会让门禁变松，不允许。"
                    )
            if isinstance(old, list) and not isinstance(new, list):
                raise ConfigError(f"spec.{section}.{key} 是列表，配置也必须给列表")
            target[key] = new
            applied.append(f"spec.{section}.{key}: {old} → {new}")
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
        for pattern in rule["patterns"]:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"规则 {rid} 的 pattern 不是合法正则：{pattern}（{exc}）") from exc
        rules.append(rule)
        existing.add(rid)
        applied.append(f"rules += {rid}")
    return applied


def _apply_whitelist(extra) -> list:
    """校验并返回白名单正则（内容而非摘要——调用方要拿它去实际静音匹配）。"""
    if not extra:
        return []
    if not isinstance(extra, list):
        raise ConfigError("whitelist_append 必须是列表")
    valid = []
    for pattern in extra:
        if not isinstance(pattern, str):
            raise ConfigError("whitelist_append 每项必须是字符串正则")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"白名单 pattern 不是合法正则：{pattern}（{exc}）") from exc
        valid.append(pattern)
    return valid
