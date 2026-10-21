# -*- coding: utf-8 -*-
"""Pytest 公共 fixture：把 scripts/ 加入 sys.path，使各脚本可直接 import。"""
import os
import sys

SCRIPTS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
