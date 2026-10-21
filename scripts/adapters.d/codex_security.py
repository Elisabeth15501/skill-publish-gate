#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Codex Security 适配器：OpenAI Codex Security 代码漏洞扫描（SARIF 输出）。"""

ADAPTER = {
    "name": "codex_security",
    "display_name": "Codex Security",
    "command_template": "codex-security scan --format sarif {dir}",
    "notes": "OpenAI Codex Security 代码漏洞扫描，SARIF 输出。",
}
