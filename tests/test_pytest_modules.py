# -*- coding: utf-8 -*-
"""Pytest · 核心模块单元测试（覆盖核心功能 + 边界情况）。

覆盖脚本：ast_guard / sarif_io / config_loader / deobfuscate / sca / gate
设计：纯函数优先直接断言；SkillHubGate 用临时 skill 目录构造，跑完整 run_all。
"""
import json
import os
import sys

import pytest

import ast_guard
import sarif_io
import config_loader
import deobfuscate
import sca
import gate

REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def _make_skill(tmp_path, slug="pytest-skill", body="# Body\n", extra=None,
                front=None):
    """在 tmp_path 下造一个合法 skill 目录，返回目录路径。"""
    if front is None:
        front = (
            "---\nname: %s\nslug: %s\nversion: 1.0.0\n"
            "displayName: t\ndescription: t\nsummary: t\ntags: [a]\n---\n"
            % (slug, slug)
        )
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(front + "\n" + body, encoding="utf-8")
    if extra:
        for rel, content in extra.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
    return str(d)


# ───────────────────────── ast_guard ─────────────────────────
class TestAstGuard:
    def test_dangerous_call_detected(self):
        r = ast_guard.scan_source("os.system('id')\n", "s.py")
        assert len(r["findings"]) >= 1
        assert any("OS" in f["rule_id"] or "SYSTEM" in f["rule_id"]
                   for f in r["findings"])

    def test_benign_no_finding(self):
        r = ast_guard.scan_source("print('hello')\nx = 1 + 2\n", "ok.py")
        assert r["findings"] == []

    def test_syntax_error_is_safe(self):
        # 畸形源码不得抛异常，只进 notes
        r = ast_guard.scan_source("def f(:\n  pass\n", "bad.py")
        assert r["findings"] == []
        assert any("无法解析" in n["text"] for n in r["notes"])

    def test_noqa_exempt(self):
        # 带 # noqa 的调用应被豁免
        r = ast_guard.scan_source("os.system('id')  # noqa\n", "s.py")
        assert r["findings"] == []

    def test_scan_skill_collects(self, tmp_path):
        d = _make_skill(tmp_path, extra={"scripts/x.py": "import os\nos.system('x')\n"})
        r = ast_guard.scan_skill(d)
        assert any("OS" in f["rule_id"] or "SYSTEM" in f["rule_id"]
                   for f in r["findings"])


# ───────────────────────── sarif_io ─────────────────────────
class TestSarifIo:
    def test_fingerprint_stable_and_line_agnostic(self):
        a = sarif_io.fingerprint("R", "f.py", line=3, title="t")
        b = sarif_io.fingerprint("R", "f.py", line=99, title="t")
        assert a == b and len(a) == 16

    def test_fingerprint_differs_by_rule(self):
        assert sarif_io.fingerprint("R1", "f.py") != sarif_io.fingerprint("R2", "f.py")

    def test_looks_like_sarif(self):
        assert sarif_io.looks_like_sarif({"version": "2.1.0", "runs": [{}]})
        assert not sarif_io.looks_like_sarif({"foo": 1})

    def test_to_sarif_schema(self):
        doc = sarif_io.to_sarif(
            [{"rule_id": "X", "severity": "high", "file": "a.py", "line": 1,
              "found": "f", "category": "SECURITY", "recommendation": "r"}])
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"] == "skill-publish-gate"

    def test_from_sarif_downgrades_when_untrusted(self):
        sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "ext", "rules": [
                {"id": "E1", "properties": {"category": "SECURITY"}}]}},
            "results": [{"ruleId": "E1", "level": "error",
                        "message": {"text": "boom"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 5}}}]}]}]}
        issues = sarif_io.from_sarif(sarif, trusted=False, source="l2")
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"  # 封顶 medium
        assert issues[0]["source"] == "l2"

    def test_from_sarif_trusted_keeps(self):
        sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "ext", "rules": [
                {"id": "E1", "properties": {"category": "SECURITY"}}]}},
            "results": [{"ruleId": "E1", "level": "error",
                        "message": {"text": "boom"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "a.py"},
                            "region": {"startLine": 5}}}]}]}]}
        issues = sarif_io.from_sarif(sarif, trusted=True, source="l2")
        assert issues[0]["severity"] == "critical"

    def test_dedupe_removes_same(self):
        iss = [{"rule_id": "R", "file": "a.py", "line": 1, "title": "t",
                "severity": "low", "found": "x"},
               {"rule_id": "R", "file": "a.py", "line": 1, "title": "t",
                "severity": "low", "found": "y"}]
        kept, dropped = sarif_io.dedupe(iss)
        assert len(kept) == 1 and len(dropped) == 1


# ───────────────────────── config_loader ─────────────────────────
class TestConfigLoader:
    def test_load_config_json(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"platform": "github"}), encoding="utf-8")
        cfg = config_loader.load_config(str(p))
        assert cfg["platform"] == "github"

    def test_load_config_missing_raises(self):
        with pytest.raises(config_loader.ConfigError):
            config_loader.load_config("/no/such/file.json")

    def test_reject_risky_pattern_blocks_redos(self):
        # 危险正则（灾难性回溯）必须被拒，不能静默放过
        with pytest.raises(config_loader.ConfigError):
            config_loader._reject_risky_pattern(r"(a+)+$", "X")

    def test_reject_risky_pattern_allows_safe(self):
        # 安全正则应原样通过
        config_loader._reject_risky_pattern(r"os\.system", "Y")  # 不抛


# ───────────────────────── deobfuscate ─────────────────────────
class TestDeobfuscate:
    def test_base64_blob_decodes(self):
        import base64
        payload = base64.b64encode(b"os.system('id')").decode()
        out = deobfuscate.deobfuscate_blob(payload)  # 返回每层解码文本列表
        assert isinstance(out, list) and out
        assert any("os.system" in layer for layer in out)

    def test_scan_plaintext_metadata_ip(self):
        hits = deobfuscate.scan_plaintext("url = http://169.254.169.254/latest")
        assert len(hits) >= 1

    def test_scan_plaintext_benign(self):
        assert deobfuscate.scan_plaintext("hello world") == []

    def test_garbage_no_crash(self):
        # 非 base64/hex 的随机串不得抛异常
        deobfuscate.deobfuscate_blob("!!!not encoded@@@")


# ───────────────────────── sca ─────────────────────────
class TestSca:
    def test_parse_version(self):
        assert sca.parse_version("1.2.3") == (1, 2, 3)
        assert sca.parse_version("v2.0") == (2, 0, 0)
        assert sca.parse_version("garbage") == (0, 0, 0)

    def test_in_range(self):
        assert sca._in_range("2.31.0", "0", "2.32.0") is True
        assert sca._in_range("2.32.0", "0", "2.32.0") is False

    def test_scan_skill_cve_hit(self, tmp_path):
        d = _make_skill(tmp_path, extra={"requirements.txt": "pyyaml==5.3.1\n"})
        res = sca.scan_skill(d)
        assert any(f["rule_id"] == "SCA-CVE-001" for f in res["findings"])

    def test_scan_skill_typosquat(self, tmp_path):
        d = _make_skill(tmp_path,
                        extra={"scripts/x.py": "import reqeusts\n"})
        res = sca.scan_skill(d)
        assert any(f["rule_id"] == "SCA-TYPOSQUAT-001" for f in res["findings"])

    def test_to_sbom_cyclonedx(self, tmp_path):
        d = _make_skill(tmp_path, extra={"requirements.txt": "requests==2.32.0\n"})
        bom = sca.to_sbom(d, skill_name="pytest-skill", version="1.0.0")
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["metadata"]["component"]["name"] == "pytest-skill"
        assert any(c["name"] == "requests" and c["version"] == "2.32.0"
                   for c in bom["components"])
        # purl 合法性
        assert any(c["purl"].startswith("pkg:pypi/requests@")
                   for c in bom["components"])


# ───────────────────────── gate (verdict / report / cross) ─────────────────────────
class TestGateCore:
    def _gate(self, tmp_path, **kw):
        d = _make_skill(tmp_path, **kw)
        g = gate.SkillHubGate(d, use_git=False, platform="skillhub", config={})
        g.run_all()
        return g

    def test_verdict_pass_on_clean_skill(self, tmp_path):
        g = self._gate(tmp_path)
        v = g.verdict()
        assert v["verdict"] == "PASS"
        assert v["exit_code"] == 0

    def test_report_lang_switch(self, tmp_path):
        g = self._gate(tmp_path)
        zh = g.report(fmt="text", lang="zh")
        en = g.report(fmt="text", lang="en")
        assert "结论" in zh and "Verdict" in en

    def test_report_html_lang(self, tmp_path):
        g = self._gate(tmp_path)
        zh = g.report(fmt="html", lang="zh")
        en = g.report(fmt="html", lang="en")
        assert 'lang="zh"' in zh and 'lang="en"' in en

    def test_report_json_contains_verdict(self, tmp_path):
        g = self._gate(tmp_path)
        j = json.loads(g.report(fmt="json", lang="zh"))
        assert j["verdict"]["verdict"] == "PASS"

    def test_cross_verify_counts(self):
        spg = [{"rule_id": "A", "file": "f.py", "line": 1, "title": "t",
                "severity": "high", "found": "x"},
               {"rule_id": "B", "file": "g.py", "line": 1, "title": "t",
                "severity": "medium", "found": "y"}]
        ext = [{"rule_id": "A", "file": "f.py", "line": 1, "title": "t",
                "severity": "medium", "found": "x"}]
        cv = gate.cross_verify(spg, ext)
        assert cv["common"] == 1
        assert cv["spg_only"] == 1
        assert cv["ext_only"] == 0
        assert cv["spg_total"] == 2 and cv["ext_total"] == 1

    def test_blocked_when_malicious(self, tmp_path):
        d = _make_skill(tmp_path,
                        extra={"scripts/x.py": "import os\nos.system('id')\n"})
        g = gate.SkillHubGate(d, use_git=False, platform="skillhub", config={})
        g.run_all()
        assert g.verdict()["verdict"] == "BLOCKED"

    def test_i18n_covers_both(self):
        assert gate.SkillHubGate._i18n("verdict", "zh") == "结论"
        assert gate.SkillHubGate._i18n("verdict", "en") == "Verdict"
        # 未知语言回退 zh
        assert gate.SkillHubGate._i18n("verdict", "fr") == "结论"
