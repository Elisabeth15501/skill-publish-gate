#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SARIF 2.1.0 双向编解码 + 统一指纹 + baseline 误报抑制。

为什么单独成模块（而不是塞进 gate.py）：
  gate.py 的职责是「判定一个 skill 目录能不能发布」，SARIF 的职责是「把判定结果
  翻译成一种别人也认的格式」。两者变化频率不同——平台规则库随平台调整，SARIF
  结构是 OASIS 固定标准。拆开后 gate.py 不必知道 SARIF 的字段名，本模块也不必
  知道 SkillHub 的封禁文件清单，各自可独立替换。

三个对外能力，都刻意做成纯函数（无 IO、无全局状态），便于 fixture 直接断言：
  1. to_sarif()   —— 把 gate 的 issue 列表导出为 SARIF 2.1.0（喂 GitHub Code Scanning 等）
  2. from_sarif() —— 把任意外部扫描器（domsec / SkillSpector / Codex Security）
                     输出的 SARIF 读回成统一 issue 结构，纳入同一个 verdict
  3. fingerprint() / load_baseline() / apply_baseline()
                   —— 跨工具可比对的指纹键 + 「确认过的误报」基线抑制

指纹口径（跨工具去重的唯一依据，改动即破坏兼容性）：
    sha256(rule_id | file | line | title) 的前 16 位十六进制
`title` 取不到时退回 rule_id。这让「同一规则、同一位置」的重复报告天然折叠，
也是 baseline 能跨版本存活的前提——文案改了、行号动了，指纹就变，基线失效。

L2 降级规则（安全默认值，不可由调用方绕过）：
    外部扫描器的 finding 一律降一级，且标 source="l2"。
    依据：LLM 语义层实测精度约 87%，把它的 critical 直接当 BLOCKER 会被误报
    轰炸，用户随后只会把工具关掉——那才是更糟的结局。只有调用方显式声明
    该工具的 finding 已过验证层，才允许不降级。
"""

from __future__ import annotations

import hashlib
import json
import os
import re

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "skill-publish-gate"
TOOL_URI = "https://github.com/Elisabeth15501/skill-publish-gate"

# gate 严重度 → SARIF level。SARIF 只有三档，critical 与 high 同归 error，
# 这是标准的有损映射，不是本工具的取舍失误。
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# L2 降级表：外部 finding 的档位**封顶 medium**（对抗式审查 S2）。
#
# 为什么不是「降一级」：降一级是 critical→high，而 high 仍在 BLOCKER_SEVERITIES 里，
# 实测 level=error 的外部 finding 照样 BLOCKED exit 1 —— 与 SKILL.md / README /
# CHANGELOG 三处「L2 一律降一级且不阻断」的承诺直接矛盾。
#
# 真正的设计意图是「深度层只能提供线索，不能单独决定发布与否」：
# LLM 语义层实测精度约 87%，把它的判断直接当 BLOCKER 会被误报轰炸，
# 用户随后只会把工具关掉 —— 那才是更糟的结局。
# medium 是 NEEDS_FIX：会出现在报告里、会让 verdict 变黄，但不阻断。
# 只有调用方显式声明该工具的 finding 已过验证层（--sarif-trusted），
# 才恢复 SARIF level 映射出来的原始档位。
_L2_DOWNGRADE = {
    "critical": "medium",
    "high": "low",
    "medium": "low",
    "low": "low",
}

# SARIF level → gate 严重度（导入方向的反向映射）。
_LEVEL_TO_SEVERITY = {
    "error": "critical",
    "warning": "medium",
    "note": "low",
    "none": "low",
}

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")

# 来源前缀：本门禁给外部 finding 的 rule_id 加的标记，形如 "L2-SARIF-RULE-001"。
# 只用于展示与归类，**不进指纹**（见 issue_fingerprint 的说明）。
_SOURCE_PREFIX_RE = re.compile(r"^(?:L\d+|EXT)-", re.I)

# 基线文件格式版本。2 = 指纹不再含行号（对抗式审查 M1）。旧版读入时会失配并给提示。
BASELINE_SCHEMA = 2


# ═══════════════════════════════════════════════════════════════
#  指纹
# ═══════════════════════════════════════════════════════════════

def fingerprint(rule_id, file, line=None, title="", occurrence=None) -> str:
    """返回跨工具可比对的指纹键。

    取前 16 位十六进制（64 bit）而非全长：指纹只用于去重与基线匹配，不是
    安全边界，碰撞概率在单仓规模下可忽略；短键让 baseline.json 保持可读。

    **不把行号计入指纹**（对抗式审查 M1）。原因：行号是最易变的字段——在文件开头
    加一行注释，后面所有 finding 的行号都平移，整份基线当场失效，基线也就失去了意义。
    基线的用途是「记住我确认过这些是误报」，而人记住的是「哪个文件的哪条规则」，
    不是「第几行」。

    但**同一文件同一规则可能命中多处**（例如 requirements.txt 里三行都没钉版）。
    直接去掉行号会把它们折叠成一条，导致「报 3 条」变成「报 1 条」，那是漏报。
    所以由调用方传入 `occurrence`（同一 文件+规则 下的第几次命中，从 0 开始），
    它的稳定性远好于行号：改别的行不会影响它，只有增删同规则的命中才会变。

    兼容性：旧指纹（含行号）不再匹配，load_baseline 会据此提示重建基线。
    """
    key = "|".join([
        str(rule_id or ""),
        str(file or ""),
        "" if occurrence is None else str(occurrence),
        str(title or rule_id or ""),
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def issue_fingerprint(issue: dict, occurrence=None) -> str:
    """从 gate 的 issue 字典取指纹。

    指纹不含 `found`（命中原文）与 `line`（对抗式审查 M1：行号最易变，
    在文件开头加一行注释就会让整份基线失效）。
    `occurrence` 由调用方按「同一 文件+规则 下的第几次命中」传入，
    见 fingerprint() 的 docstring 说明为什么需要它。

    **rule_id 取去掉来源前缀的原值**（对抗式审查 P1-7 / G4）。L2 的 rule_id 会被
    加上 `L2-` 前缀以区分来源，若指纹用带前缀的值，L0 与 L2 报同一件事就永远
    折叠不掉——「跨工具去重」会变成一句空话。前缀只用于展示与字典归类，不进指纹。
    """
    raw_rule_id = _strip_source_prefix(issue.get("rule_id", ""))
    return fingerprint(
        raw_rule_id,
        issue.get("file", ""),
        occurrence=occurrence,
        title=issue.get("title", ""),
    )


def issue_identity(issue: dict) -> str:
    """问题的「身份键」：文件 + 规则，**不含来源前缀、不含行号、不含 occurrence**。

    这是跨工具去重真正该用的键。L0 报 FORB-001@a.md:3、L2 报同一件事时，
    两者身份键相同 → 折叠成一条；而同一来源在同一文件报两次（两条未钉版的依赖）
    身份键也相同——**所以它不能单独用于去重**，必须配合 occurrence 区分「同一来源
    的多次命中」（见 dedupe 的两阶段实现）。
    """
    return sarif_io_key(issue.get("file", ""),
                        _strip_source_prefix(issue.get("rule_id", "")),
                        issue.get("title", ""))


def sarif_io_key(file: str, rule_id: str, title: str) -> str:
    """身份键的底层实现：sha256(file | 原始rule_id | title)[:16]。

    与 fingerprint() 的差别正是「不含 occurrence」——这是跨工具去重需要的那个键。
    放在模块级而非内联，是为了让测试能直接验证键本身。
    """
    key = "|".join([str(file or ""), str(rule_id or ""), str(title or rule_id or "")])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _strip_source_prefix(rule_id: str) -> str:
    """去掉来源前缀（L2- / EXT- 等），还原成外部工具的原始 ruleId。

    前缀是本门禁加的展示用标记，不属于「问题身份」的一部分。
    """
    return _SOURCE_PREFIX_RE.sub("", rule_id or "")


def assign_occurrences(issues: list) -> list:
    """给每条 issue 标注它是自己 (file, 原始rule_id) 下的第几次命中。

    原地追加 `occurrence` 字段并返回原列表。**必须在所有指纹计算之前调用**。

    分组键 = (file, 剥离来源前缀后的 rule_id)。为什么前缀要剥：
      L0 报了一条 FORB-001，外部扫描器对**同一位置**也报了一条（L2-FORB-001），
      它们是同一件事，dedupe 应折叠成一条。若按带前缀的 rule_id 分组，
      两者会被当成两个不同的问题各自计数，指纹永不相同，去重就是空话。

    同一来源自己在同一文件报两次（requirements.txt 两行都没钉版）仍靠 occurrence
    递增区分，不会被误折叠——实测这正是「不能简单去掉 occurrence」的原因。

    注意 dedupe 的折叠判据是「身份键 + 行号」而非指纹本身：指纹为基线设计（抗行号
    漂移），而精确去重要的就是「同一行才算同一条」。两条路径用途不同，别混用。
    """
    counters: dict = {}
    for issue in sorted(issues, key=lambda i: (i.get("file", ""), i.get("line", 0),
                                               _strip_source_prefix(i.get("rule_id", "")))):
        key = (issue.get("file", ""), _strip_source_prefix(issue.get("rule_id", "")))
        idx = counters.get(key, 0)
        issue["occurrence"] = idx
        counters[key] = idx + 1
    return issues


# ═══════════════════════════════════════════════════════════════
#  出口：gate issue → SARIF 2.1.0
# ═══════════════════════════════════════════════════════════════

def _rule_metadata(issues: list) -> list:
    """从 issue 列表派生 runs[].tool.driver.rules（去重、保序）。

    SARIF 要求每条 result 的 ruleId 都能在 driver.rules 里查到定义，
    否则 GitHub Code Scanning 会拒收整份文件。
    """
    rules = []
    seen = set()
    for issue in issues:
        rid = issue.get("rule_id") or "UNSPECIFIED"
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({
            "id": rid,
            "name": _rule_name(rid),
            "shortDescription": {"text": issue.get("recommendation") or rid},
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(issue.get("severity", "medium"), "warning"),
            },
            "properties": {
                "category": issue.get("category", ""),
                "redline": bool(issue.get("redline")),
                "authorityType": issue.get("authority_type", ""),
            },
        })
    return rules


def _rule_name(rule_id: str) -> str:
    """SEC-CRED-001 → SecCred001：ruleId 里的连字符不是合法标识符字符。"""
    return re.sub(r"[^0-9a-zA-Z]+", "", rule_id) or "Rule"


def to_sarif(issues: list, tool_version: str = "", spec_version: str = "") -> dict:
    """把 gate 的 issue 列表导出为一份合法的 SARIF 2.1.0 文档。

    指纹写进 partialFingerprints（而非自造顶层字段）：这是 SARIF 2.1.0 规范里
    专为主机工具存放「跨运行稳定标识」的位置，GitHub 会用它跟踪同一问题是否复发。
    """
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": tool_version,
                    "informationUri": TOOL_URI,
                    "rules": _rule_metadata(issues),
                },
            },
            "results": [_to_result(i) for i in issues],
            "properties": {"specVersion": spec_version},
        }],
    }


def _to_result(issue: dict) -> dict:
    """单条 issue → SARIF result。uri 用 posix 斜杠（规范要求 URI 形式）。"""
    rule_id = issue.get("rule_id") or "UNSPECIFIED"
    result = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL.get(issue.get("severity", "medium"), "warning"),
        "message": {"text": issue.get("recommendation") or issue.get("found", "")},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(issue.get("file", "")).replace(os.sep, "/"),
                },
                "region": {"startLine": max(1, int(issue.get("line") or 1))},
            },
        }],
        "partialFingerprints": {TOOL_NAME: issue_fingerprint(issue)},
        "properties": {
            "severity": issue.get("severity", ""),
            "category": issue.get("category", ""),
            "redline": bool(issue.get("redline")),
            "clause": issue.get("clause", ""),
        },
    }
    # source=l2 表示这条来自外部扫描器而非本门禁，消费方（CI 报告）可据此分级处理
    if issue.get("source"):
        result["properties"]["source"] = issue["source"]
    return result


# ═══════════════════════════════════════════════════════════════
#  入口：外部 SARIF → gate issue
# ═══════════════════════════════════════════════════════════════

def looks_like_sarif(doc) -> bool:
    """宽松判断一份已解析的 JSON 是否是 SARIF——只认这两个必备字段即可。"""
    return isinstance(doc, dict) and doc.get("version", "").startswith("2.") and "runs" in doc


def _as_dict(value) -> dict:
    """把可能是 None / 非 dict 的值安全转成 dict。

    为什么必须有这个：SARIF 里 `message: null`、`properties: null` 是**合法且常见**的
    （分析器作者显式置空），而 `d.get(k, {})` 在「key 存在但值为 null」时返回的是
    `None` 而不是 `{}` —— 于是 `.get("text")` 直接 AttributeError。
    本模块承诺「畸形输入不抛异常」，所有外部字段都必须先过这一道。
    """
    return value if isinstance(value, dict) else {}


def _as_text(container, key: str, limit: int = 0) -> str:
    """从可能为 None 的容器里取字符串，截断到 limit（0 = 不截断）。"""
    text = _as_dict(container).get(key, "")
    if not isinstance(text, str):
        text = str(text)
    return text[:limit] if limit else text


def from_sarif(doc: dict, trusted: bool = False, source: str = "l2") -> list:
    """把外部 SARIF 2.1.0 读成 gate 的 issue 列表。

    对畸形输入刻意宽容：任何一个 run / result / location 缺字段或为 null 都只跳过该条，
    不抛异常。理由是「外部工具的输出不该让门禁崩掉」——崩了就等于逼用户关掉
    --sarif-in，而不是去修对方的输出。

    trusted=True 表示调用方已确认该工具的 finding 过验证层，此时**不封顶**、
    恢复原始档位。未信任时一律封顶 medium（见 _L2_DOWNGRADE 的说明），
    所以 L2 永远不能单独把一个 skill 判成 BLOCKED。
    """
    issues = []
    if not looks_like_sarif(doc):
        return issues
    for run in doc.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
        rule_meta = {r.get("id"): r for r in (driver.get("rules") or [])
                     if isinstance(r, dict)}
        for result in run.get("results") or []:
            issue = _from_result(result, rule_meta, trusted, source)
            if issue:
                issues.append(issue)
    return issues


def _from_result(result, rule_meta: dict, trusted: bool, source: str) -> dict:
    """单条 SARIF result → gate issue；结构不完整返回 None。"""
    if not isinstance(result, dict):
        return None
    location = _first_location(result)
    rule_id = result.get("ruleId") or "L2-UNSPECIFIED"
    meta = rule_meta.get(rule_id) or {}
    severity = _severity_of(result, meta)
    if not trusted:
        severity = _L2_DOWNGRADE.get(severity, "low")
    message = result.get("message")
    return {
        "rule_id": f"{source.upper()}-{rule_id}",
        "category": _as_dict(meta.get("properties")).get("category", "SECURITY"),
        "severity": severity,
        "file": location["file"],
        "line": location["line"],
        "found": _as_text(message, "text", 80),
        "recommendation": _as_text(meta.get("shortDescription"), "text")
                          or _as_text(message, "text", 200),
        # 外部 finding 一律不算红线：redline 的语义是「平台协议判定不可发布」，
        # 那是本门禁对平台规则的解释权，不该被 L2 结果借用。
        "redline": False,
        "authority_type": "external_tool",
        "clause": f"外部扫描器：{_tool_label(meta, rule_id)}",
        "source": source,
        "trusted": trusted,
        "title": rule_id,
    }


def _tool_label(meta: dict, rule_id: str) -> str:
    """报告里指明 finding 来自哪个外部工具（仅影响可读性，不影响判定）。"""
    return meta.get("name") or rule_id or "external"


def _first_location(result: dict) -> dict:
    """取第一条物理位置；缺失时归到 (unknown, 1) 而不是丢弃整条结果。"""
    locs = result.get("locations") or []
    if not locs or not isinstance(locs[0], dict):
        return {"file": "(external)", "line": 1}
    phys = locs[0].get("physicalLocation") or {}
    uri = (phys.get("artifactLocation") or {}).get("uri", "(external)")
    start = (phys.get("region") or {}).get("startLine", 1)
    try:
        line = max(1, int(start))
    except (TypeError, ValueError):
        line = 1
    return {"file": str(uri), "line": line}


def _severity_of(result: dict, meta: dict) -> str:
    """严重度优先取 properties.severity（保留原始档位），否则由 level 反推。"""
    explicit = _as_dict(result.get("properties")).get("severity")
    if isinstance(explicit, str) and explicit in _LEVEL_TO_SEVERITY:
        return explicit
    level = result.get("level") or _as_dict(
        meta.get("defaultConfiguration")).get("level")
    return _LEVEL_TO_SEVERITY.get(level, "medium")


# ═══════════════════════════════════════════════════════════════
#  跨工具去重 + baseline 误报抑制
# ═══════════════════════════════════════════════════════════════

def dedupe(issues: list) -> tuple:
    """折叠重复项，返回 (保留项, 被折叠项)。

    判据是「身份键 + 行号」：`身份键 = file + 原始 rule_id`（不含来源前缀），
    再加上行号一起构成「同一个问题的同一个位置」。

    为什么这个判据能同时满足两个相反的要求（对抗式审查 P1-7 / G4 / M1）：
      · L0 报 FORB-001@a.md:3，外部扫描器报 L2-FORB-001@a.md:3 → 剥前缀后身份键相同、
        行号相同 → 折叠。**跨工具去重真正生效。**
      · 同一来源在同一文件报三次（requirements.txt 三行都没钉版）→ 身份键相同但
        行号各不相同 → 三条都保留。**同文件多行不会被误折叠成一条。**
      · 行号漂移（文件开头插一行）不影响基线，因为基线走的是不含行号的指纹
        （见 M1 与 apply_baseline），与这里的「精确去重」是两条不同的路径。

    「保留」取先到的那条：调用方按 L0 → L2 顺序追加，本门禁自己的结论天然排在前面，
    冲突时以本门禁为准。
    """
    assign_occurrences(issues)
    kept, dropped, seen = [], [], set()
    for issue in issues:
        key = (issue_identity(issue), issue.get("line"))
        if key in seen:
            dropped.append(issue)
            continue
        seen.add(key)
        kept.append(issue)
    return kept, dropped


def load_baseline(path: str) -> tuple:
    """读基线文件，返回 (指纹集合, 提示信息)。

    文件不存在 = 空基线（首次运行属正常）。**旧版 schema 1 的基线（指纹含行号）
    会全部失配**，所以额外返回一句提示，让用户知道「基线失效」是重算口径造成的，
    而不是「误报又回来了」。
    """
    empty = (set(), "")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return empty
    entries = data.get("fingerprints") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return empty
    # 只认真指纹：手工往 baseline 里塞别的字符串会让「抑制」变成万能豁免口
    valid = {e for e in entries if isinstance(e, str) and _FINGERPRINT_RE.match(e)}
    note = ""
    if isinstance(data, dict) and data.get("schema", 1) < BASELINE_SCHEMA:
        note = (f"基线文件是旧版 schema（指纹含行号），已不兼容——"
                f"行号变动会使基线整体失效（对抗式审查 M1）。"
                f"请用 --write-baseline 重建。")
    return valid, note


def save_baseline(path: str, issues: list, verdict: str = "", skipped: int = 0) -> int:
    """把 issue 的指纹写成基线文件，返回写入条数。

    `skipped` 是被调用方挡在外面的 blocker 数量——写进文件是为了让基线**自证**：
    半年后有人翻到这个文件时，能看到「当时有 3 条 blocker 没被写进来」，
    而不是误以为基线已经涵盖了全部问题。
    """
    assign_occurrences(issues)
    fingerprints = sorted({issue_fingerprint(i, i.get("occurrence")) for i in issues})
    payload = {
        "tool": TOOL_NAME,
        "schema": BASELINE_SCHEMA,
        "generated_from_verdict": verdict,
        "skipped_blockers": skipped,
        "fingerprints": fingerprints,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return len(fingerprints)


def apply_baseline(issues: list, baseline: set) -> tuple:
    """把命中基线的 issue 降级为 info，返回 (保留项, 被抑制项的 info 记录)。

    被抑制的项不删除、只降为 info 级——「当初为什么放过它」必须仍可追溯，
    否则基线就成了无法审计的黑洞。一次遍历同时产出两个结果，调用方无需关心
    先后顺序（拆成两个函数就留下了一个「必须按序调用」的隐含契约）。
    """
    if not baseline:
        return issues, []
    assign_occurrences(issues)
    kept, suppressed = [], []
    for issue in issues:
        fp = issue_fingerprint(issue, issue.get("occurrence"))
        if fp not in baseline:
            kept.append(issue)
        else:
            suppressed.append({
                "rule_id": issue.get("rule_id", ""),
                "category": issue.get("category", ""),
                "severity": "info",
                "file": issue.get("file", ""),
                "line": issue.get("line", 0),
                "found": issue.get("found", ""),
                "recommendation": "已在基线中（确认过的误报），本次已抑制；"
                                  "若问题已真实修复，执行 --write-baseline 重建基线。",
                "redline": False,
                "authority_type": issue.get("authority_type", ""),
                "clause": issue.get("clause", ""),
                "fingerprint": fp,
            })
    return kept, suppressed
