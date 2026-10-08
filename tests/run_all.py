#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跑完 tests/ 下全部测试，汇总结果。

用法（在仓库根目录或任意位置）：
    python tests/run_all.py

为什么要有这个入口：门禁本身是「发布前的最后一道闸」，
如果回归测试只能靠记住五个文件名逐个跑，三个月后就没人跑了。
一个命令 + 明确的失败退出码，是让回归保护真正存在的前提。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
# 单个测试的最长运行时间；超了算失败而不是无限等
PER_TEST_TIMEOUT = 600

TESTS = [
    "test_modules.py",       # 三个模块的单元测试（含 P0-1/3 的攻击断言）
    "test_e2e.py",           # 端到端 fixture（C3/C4/ast/SARIF/config/baseline/ima）
    "test_p0_verify.py",     # 三个原始攻击 + S2/S6 的原样重打
    "test_p17_verify.py",    # 跨工具去重 + 指纹抗行号漂移
    "test_m3_verify.py",     # feedback 原子写与并发
]


def main() -> int:
    results = []
    for name in TESTS:
        path = os.path.join(HERE, name)
        if not os.path.isfile(path):
            results.append((name, "SKIP", 0.0, "文件不存在"))
            continue
        t0 = time.perf_counter()
        try:
            proc = subprocess.run([PY, path], capture_output=True, text=True,
                                  timeout=PER_TEST_TIMEOUT, check=False)
            dt = time.perf_counter() - t0
            results.append((name, "PASS" if proc.returncode == 0 else "FAIL", dt,
                            (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else ""))
        except subprocess.TimeoutExpired:
            dt = time.perf_counter() - t0
            results.append((name, "TIMEOUT", dt, f"超过 {PER_TEST_TIMEOUT}s"))

    print("=" * 64)
    print(f"{'测试':<24} {'结果':<8} {'耗时':>8}  备注")
    print("-" * 64)
    for name, verdict, dt, note in results:
        icon = {"PASS": "✅", "FAIL": "❌", "TIMEOUT": "⏱", "SKIP": "—"}[verdict]
        print(f"{name:<24} {icon} {verdict:<5} {dt:>6.1f}s  {note[:20]}")
    failed = [r for r in results if r[1] != "PASS"]
    print("=" * 64)
    if failed:
        print(f"❌ {len(failed)} 个测试未通过")
        return 1
    print(f"✅ 全部 {len(results)} 个测试通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
