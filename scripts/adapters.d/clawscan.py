#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ClawScan 适配器：OpenClaw 风险扫描（ClawHub 生态）。"""

ADAPTER = {
    "name": "clawscan",
    "display_name": "ClawScan",
    "command_template": "clawscan --format sarif {dir}",
    "notes": "OpenClaw 风险扫描（ClawHub 生态）。",
}
