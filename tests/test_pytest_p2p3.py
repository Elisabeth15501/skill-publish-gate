# -*- coding: utf-8 -*-
"""Pytest · P2/P3 新能力测试（远程/归档 + 适配器 SDK + SBOM + 双向对标 + 多语言）。

覆盖核心功能与边界：
  P2-1 远程/归档扫描（_acquire_target）：本地归档解包、离线禁用、文件缺失、坏 zip
  P2-2 适配器 SDK（adapters）：注册表发现、未知名、真实 SARIF 解析与 L2 降级
  P2-3 SBOM：CycloneDX 结构（已在 test_pytest_modules 覆盖 to_sbom，这里验 gate 集成）
  P3-1 双向对标：cross_verify 已覆盖，这里验 report json 携带 cross_verify
  P3-3 多语言：lang 已覆盖，这里验 json 报告 cross/sbom 字段贯通
"""
import argparse
import json
import os
import sys
import types
import zipfile

import pytest

import gate
import adapters
import sca


def _args(**kw):
    a = types.SimpleNamespace()
    a.dir = kw.get("dir")
    a.repo = kw.get("repo")
    a.archive = kw.get("archive")
    a.offline = kw.get("offline", False)
    return a


def _make_skill(tmp_path, slug="pytest-skill", body="# Body\n", extra=None):
    front = ("---\nname: %s\nslug: %s\nversion: 1.0.0\ndisplayName: t\n"
             "description: t\nsummary: t\ntags: [a]\n---\n" % (slug, slug))
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(front + "\n" + body, encoding="utf-8")
    if extra:
        for rel, content in extra.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
    return str(d)


# ───────────────────────── P2-1 远程/归档 ─────────────────────────
class TestAcquireTarget:
    def test_local_archive_unpack(self, tmp_path):
        src = _make_skill(tmp_path, slug="arch")
        zp = str(tmp_path / "a.zip")
        with zipfile.ZipFile(zp, "w") as z:
            for f in os.listdir(src):
                z.write(os.path.join(src, f), arcname=f)
        scan_dir, tmp_root = gate._acquire_target(_args(archive=zp))
        try:
            assert os.path.isdir(scan_dir)
            assert os.path.isfile(os.path.join(scan_dir, "SKILL.md"))
            assert tmp_root and os.path.isdir(tmp_root)
        finally:
            import shutil
            if tmp_root:
                shutil.rmtree(tmp_root, ignore_errors=True)

    def test_missing_archive_errors(self, tmp_path):
        with pytest.raises(SystemExit) as ei:
            gate._acquire_target(_args(archive=str(tmp_path / "nope.zip")))
        assert ei.value.code == 2

    def test_bad_zip_errors(self, tmp_path):
        bad = tmp_path / "bad.zip"
        bad.write_bytes(b"not a zip")
        with pytest.raises(SystemExit) as ei:
            gate._acquire_target(_args(archive=str(bad)))
        assert ei.value.code == 2

    def test_offline_repo_rejected(self, tmp_path):
        with pytest.raises(SystemExit) as ei:
            gate._acquire_target(_args(repo="https://x/y.git", offline=True))
        assert ei.value.code == 2

    def test_local_dir_passthrough(self, tmp_path):
        d = _make_skill(tmp_path)
        scan_dir, tmp_root = gate._acquire_target(_args(dir=d))
        assert scan_dir == d and tmp_root is None


# ───────────────────────── P2-2 适配器 SDK ─────────────────────────
class TestAdapters:
    def test_registry_has_four_builtins(self):
        reg = adapters.load_registry()
        for name in ("domsec", "skillspector", "codex_security", "clawscan"):
            assert name in reg
            assert "command_template" in reg[name]

    def test_unknown_adapter_returns_note(self, tmp_path):
        res = adapters.scan_with_adapter("does_not_exist", str(tmp_path))
        assert res["issues"] == []
        assert any("未知适配器" in n for n in res["notes"])

    def test_run_adapter_parses_sarif(self, tmp_path):
        # 造一个会输出合法 SARIF 的桩脚本，验证 run_adapter 解析 + L2 降级
        sarif = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "stub", "rules": [
                {"id": "STUB-1", "properties": {"category": "SECURITY"}}]}},
            "results": [{"ruleId": "STUB-1", "level": "error",
                        "message": {"text": "found it"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "x.py"},
                            "region": {"startLine": 3}}}]}]}]}
        stub = tmp_path / "stub_emitter.py"
        stub.write_text(
            "import sys,json\n"
            "sys.stdout.write(json.dumps(%s))\n" % json.dumps(sarif),
            encoding="utf-8")
        adapter = {"name": "stub", "display_name": "stub",
                   "command_template": "%s %s {dir}" % (sys.executable, stub)}
        res = adapters.run_adapter(adapter, str(tmp_path))
        assert len(res["issues"]) == 1
        # 外部结果按 L2 降一级 → medium
        assert res["issues"][0]["severity"] == "medium"
        assert res["issues"][0]["source"] == "l2"

    def test_run_adapter_missing_tool_graceful(self, tmp_path):
        adapter = {"name": "absent", "display_name": "absent",
                   "command_template": "this_tool_does_not_exist_xyz {dir}"}
        res = adapters.run_adapter(adapter, str(tmp_path))
        assert res["issues"] == []
        assert any("找不到可执行" in n for n in res["notes"])


# ───────────────────────── P2-3 / P3-1 / P3-3 报告贯通 ─────────────────────────
class TestReportIntegration:
    def _gate(self, tmp_path, **kw):
        d = _make_skill(tmp_path, **kw)
        g = gate.SkillHubGate(d, use_git=False, platform="skillhub", config={})
        g.run_all()
        return g

    def test_json_includes_sbom(self, tmp_path):
        d = _make_skill(tmp_path, extra={"requirements.txt": "requests==2.32.0\n"})
        g = self._gate(tmp_path)
        bom = sca.to_sbom(d, skill_name="pytest-skill")
        j = json.loads(g.report(fmt="json", lang="zh", sbom=bom))
        assert j["sbom"]["bomFormat"] == "CycloneDX"
        assert j["sbom"]["components"]

    def test_json_includes_cross_verify(self, tmp_path):
        g = self._gate(tmp_path)
        ext = [{"rule_id": "A", "file": "SKILL.md", "line": 1, "title": "t",
                "severity": "medium", "found": "x"}]
        cv = gate.cross_verify([], ext)
        j = json.loads(g.report(fmt="json", lang="zh", cross=cv))
        assert j["cross_verify"]["ext_total"] == 1
        assert "spg_only" in j["cross_verify"]

    def test_text_includes_cross_section(self, tmp_path):
        g = self._gate(tmp_path)
        ext = [{"rule_id": "A", "file": "SKILL.md", "line": 1, "title": "t",
                "severity": "medium", "found": "x"}]
        cv = gate.cross_verify([], ext)
        out = g.report(fmt="text", lang="zh", cross=cv)
        assert "双向对标" in out and "仅外部报出" in out
