#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domsec 适配器：OpenClaw 风险扫描（不安全配置 / Skill 风险 / CVE / 隐私泄漏）。"""

ADAPTER = {
    "name": "domsec",
    "display_name": "domsec (OpenClaw 风险扫描)",
    "command_template": "domsec scan --format sarif {dir}",
    "notes": "OpenClaw 风险：不安全配置/Skill 风险/CVE/隐私泄漏。",
}
