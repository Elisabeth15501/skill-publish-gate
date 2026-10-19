#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反混淆预检层（P0-1）：解缠常见静态混淆手法，暴露隐藏的恶意载荷。

定位：给「代码安全」检查一个「把 base64 / hex / zlib 嵌套 blob 展开」的能力，
让绕过 check_rules / check_ast_dangerous_calls 的混淆代码无处遁形（T03/T04 规避）。

设计约束（与 SPG 完全一致）：
  - 纯标准库、零出网、零密钥、确定性。
  - 带层数上限 + 单层解码大小上限，防 zip-bomb / 无限解缠把进程吃死。
  - 只对「长得像编码串」的片段尝试解码，避免对全文乱解造成性能/误报问题。
  - 本模块只做「解缠 + 危险 sink 暴露」，不做语义裁决；是否阻断由 gate.py 决定。
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib

_MAX_LAYERS = 5                # 最多解缠层数（够覆盖常见的 2~3 层嵌套）
_MAX_DECODED_BYTES = 1_000_000  # 单层解码产物上限 1MB，超出即停（防炸弹）

# 看起来像 base64 的片段：窄字符集、长度够长（短串解出来也没意义且误报高）
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
# 看起来像 hex 的片段：偶数长、全 hex 字符、长度够长
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")

# 解缠成功后要回查的「危险 sink」——这些才是我们真正想暴露的东西。
# 列表刻意收得很紧，只放「几乎一定是恶意意图」的强信号，避免把合法 base64
# 数据（证书/图片/配置）误判成攻击。
_DANGEROUS_SINKS = [
    ("os.system", re.compile(r"os\.system\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("exec", re.compile(r"\bexec\s*\(")),
    ("subprocess-shell", re.compile(r"subprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True", re.I | re.S)),
    ("curl-pipe-sh", re.compile(r"curl\b[^\n]*\|\s*(?:ba)?sh\b")),
    ("wget-pipe-sh", re.compile(r"wget\b[^\n]*\|\s*(?:ba)?sh\b")),
    ("reverse-shell", re.compile(r"/dev/tcp/|nc\s+-e|\bncat\b|\bsocat\b|\bbash\s+-i\s*>&\s*/dev/tcp")),
    ("metadata-ip", re.compile(r"169\.254\.169\.254")),
    ("powershell-enc", re.compile(r"powershell[^\n]*-enc\b|-EncodedCommand", re.I)),
    ("b64-decode-exec", re.compile(r"base64\.b64decode|base64\s+-d|exec\(.*b64|eval\(.*b64", re.I)),
]


# ─═════════════════════════════════════════════════════════════
#  单层解码
# ─═════════════════════════════════════════════════════════════

def _looks_b64(s: str) -> bool:
    return bool(_B64_RE.fullmatch(s)) or (
        len(s) >= 16 and bool(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s))
    )


def _looks_hex(s: str) -> bool:
    return len(s) % 2 == 0 and bool(_HEX_RE.fullmatch(s))


def _try_decode(s: str):
    """对单段字符串尝试一种解码，成功返回解码后的文本，否则 None。

    依次试 hex、base64（标准 + urlsafe）、zlib（三种 wbits）。
    任一种成功即返回；全部失败返回 None。每个分支独立 try，绝不抛出。

    注意顺序：纯 hex 串的字符集是 base64 的子集，若先试 base64 会被
    `validate=True` 当成合法 base64 解出乱码，导致 hex 分支永远走不到。
    因此纯 hex 优先解 hex——这是唯一正确的解释顺序。
    """
    # hex（纯 hex 串优先，避免被 base64 误判为有效字符集解出乱码）
    if _looks_hex(s):
        try:
            d = binascii.unhexlify(s)
            return d.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
    # base64（标准）
    if _looks_b64(s) and len(s) % 4 == 0:
        try:
            d = base64.b64decode(s, validate=True)
            return d.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
    # base64（urlsafe / 补 padding）
    if _looks_b64(s):
        try:
            d = base64.urlsafe_b64decode(s + "===")
            return d.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
    # zlib / deflate（raw bytes）
    raw = s.encode("latin-1", "replace")
    for wbits in (-15, 15, 47):
        try:
            d = zlib.decompress(raw, wbits)
            return d.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
    return None


def deobfuscate_blob(blob: str):
    """对一段疑似编码串做多层解缠，返回每层解码文本列表（最多 _MAX_LAYERS 层）。

    循环终止条件：
      (a) 某层解码失败（None）；或
      (b) 解码结果与上一层相同（已到底）；或
      (c) 解码产物超过大小上限；或
      (d) 达到层数上限。
    永不抛出。
    """
    layers = []
    current = blob
    for _ in range(_MAX_LAYERS):
        decoded = _try_decode(current)
        if decoded is None:
            break
        if len(decoded.encode("utf-8", "replace")) > _MAX_DECODED_BYTES:
            break
        layers.append(decoded)
        if decoded == current:
            break
        current = decoded
    return layers


# ─═════════════════════════════════════════════════════════════
#  行级扫描：暴露含危险 sink 的混淆片段
# ─═════════════════════════════════════════════════════════════

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}|(?:[0-9a-fA-F]{2}){12,}")

# 明文 C2 / 云元数据 IP（不依赖编码混淆，直接出现在命令串里）。
# 这些是强信号，收得很紧，避免把「说明文档里举例」误判成攻击。
_C2_PLAINTEXT = [
    ("reverse-shell", re.compile(r"/dev/tcp/|nc\s+-e|\bncat\b|\bsocat\b|\bbash\s+-i\s*>&\s*/dev/tcp")),
    ("metadata-ip", re.compile(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254")),
    ("c2-beacon", re.compile(r"curl\b[^\n]*169\.254\.169\.254|wget\b[^\n]*169\.254\.169\.254")),
]

# 自扫描豁免：本门禁自己的检测器源码（定义这些正则/字符串的那几行）不该被
# 当成攻击。命中下列任一标记的行直接跳过——它们是「定义检测规则」而非「发起攻击」。
_SELF_DETECTOR_RE = re.compile(
    r"_DANGEROUS_SINKS|_C2_PLAINTEXT|_CANDIDATE_RE|reverse-shell|metadata-ip|"
    r"re\.compile|def scan_|self\.skip|SKIP_SELF", re.I)


def scan_plaintext(line: str):
    """扫明文行里的 C2 / 云元数据 IP 强信号。返回 [{sink, found}]。

    豁免：行内出现本门禁自己的检测器源码标记时返回空（避免自扫误报）。
    """
    if _SELF_DETECTOR_RE.search(line):
        return []
    out = []
    for sink, rx in _C2_PLAINTEXT:
        m = rx.search(line)
        if m:
            out.append({"sink": sink, "found": line.strip()[:120]})
    return out


def scan_line(line: str):
    """扫描单行，对其中每个「编码串候选」解缠；若任一层暴露危险 sink，
    返回该发现的列表（每行至多一条，避免刷屏）。

    返回元素：{"sink": 危险类型, "revealed": 解缠后暴露的片段（截断）}
    """
    findings = []
    for m in _CANDIDATE_RE.finditer(line):
        token = m.group(0)
        layers = deobfuscate_blob(token)
        for dec in layers:
            for sink, rx in _DANGEROUS_SINKS:
                if rx.search(dec):
                    findings.append({
                        "sink": sink,
                        "revealed": dec.strip()[:120],
                    })
                    break
            if findings:
                break
        if findings:
            break
    return findings


# ─═════════════════════════════════════════════════════════════
#  测试入口见 tests/test_deobfuscate.py（本模块不内置 __main__ 自检，
#  避免把用于验证的恶意载荷样例留在发布产物里、反被内容红线规则命中）。
# ─═════════════════════════════════════════════════════════════

