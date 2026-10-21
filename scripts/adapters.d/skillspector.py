#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SkillSpector 适配器：技能静态审计，输出 SARIF 2.1.0。"""

ADAPTER = {
    "name": "skillspector",
    "display_name": "SkillSpector",
    "command_template": "skillspector --sarif {dir}",
    "notes": "技能静态审计，输出 SARIF 2.1.0。",
}
