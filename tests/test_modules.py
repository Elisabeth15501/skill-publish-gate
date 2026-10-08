# -*- coding: utf-8 -*-
"""v1.5.0 三个新模块的单测（一次性验证脚本，跑在临时目录，不随技能分发）。"""
import json
import os
import sys
HERE = os.path.dirname(os.path.abspath(__file__))
import tempfile

SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import ast_guard
import config_loader
import sarif_io

fails = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else f"  <- {detail}"))
    if not cond:
        fails.append(name)


print("=== 1. ast_guard：危险调用 ===")
SRC = '''
import json, os, pickle, subprocess, yaml

def bad(user_input):
    eval(user_input)
    exec(user_input)
    os.system("ls " + user_input)
    subprocess.run("ls " + user_input, shell=True)
    pickle.loads(user_input)
    yaml.load(user_input)

def safe(user_input):
    json.loads(user_input)          # 绝不能报
    data = {"a": 1}
    return json.dumps(data)

def allowed(user_input):
    eval(user_input)  # noqa: 确认过输入可信
'''
r = ast_guard.scan_source(SRC, "scripts/t.py")
ids = sorted(f["rule_id"] for f in r["findings"])
check("命中 eval/exec/os.system/shell=True/pickle/yaml.load 共 6 条",
      len(r["findings"]) == 6, f"实际 {len(r['findings'])}: {ids}")
check("json.loads 不误报", not any("json" in f["found"] for f in r["findings"]))
check("# noqa 行被豁免（eval 出现在 16 行但未报）",
      not any(f["line"] == 16 for f in r["findings"]),
      [f["line"] for f in r["findings"]])
check("行号精确（eval=5）", any(f["line"] == 5 and f["rule_id"] == "AST-EVAL-001"
                                for f in r["findings"]),
      [f["line"] for f in r["findings"]])
check("带 code 原文供核对", all(f["found"] for f in r["findings"]))

print("=== 1b. ast_guard：容错 ===")
r2 = ast_guard.scan_source("def broken(:\n  pass\n", "scripts/bad.py")
check("语法错误不抛异常且记 note", r2["findings"] == [] and len(r2["notes"]) == 1, r2)
SELF_DIR = os.path.normpath(os.path.join(HERE, ".."))
r3 = ast_guard.scan_skill(SELF_DIR)
check("扫自家 scripts 不崩", isinstance(r3["findings"], list))
print("     自家 scripts findings:", [(f["rule_id"], f["file"], f["line"]) for f in r3["findings"]] or "无")
print("     自家 scripts notes:", [(n["file"], n["text"][:40]) for n in r3["notes"]] or "无")

print("=== 2. sarif_io：往返 ===")
issues = [
    {"rule_id": "FORB-001", "category": "SPEC", "severity": "critical", "file": "a\\b.md",
     "line": 3, "found": ".gitignore", "recommendation": "删掉", "redline": True,
     "authority_type": "platform_policy", "clause": "第5.1条"},
    {"rule_id": "DEP-PIN-001", "category": "SPEC", "severity": "medium", "file": "req.txt",
     "line": 1, "found": "requests", "recommendation": "钉版", "redline": False,
     "authority_type": "best_practice", "clause": ""},
]
doc = sarif_io.to_sarif(issues, tool_version="1.5.0", spec_version="1.5.0")
check("schema/version 正确",
      doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-schema-2.1.0.json"))
check("driver.rules 派生去重（2 条）", len(doc["runs"][0]["tool"]["driver"]["rules"]) == 2)
check("critical→error / medium→warning",
      [r["level"] for r in doc["runs"][0]["results"]] == ["error", "warning"])
check("uri 用 posix 斜杠", doc["runs"][0]["results"][0]["locations"][0]
      ["physicalLocation"]["artifactLocation"]["uri"] == "a/b.md")
check("partialFingerprints 已写入",
      bool(doc["runs"][0]["results"][0]["partialFingerprints"]["skill-publish-gate"]))
check("looks_like_sarif 认出自己", sarif_io.looks_like_sarif(doc))

back = sarif_io.from_sarif(doc)
check("往返条数一致", len(back) == 2, len(back))
check("往返后 rule_id 加 L2- 前缀", all(i["rule_id"].startswith("L2-") for i in back))
check("L2 封顶 medium：error→medium, warning→low（S2）",
      [i["severity"] for i in back] == ["medium", "low"], [i["severity"] for i in back])
check("L2 无 critical/high（不可单独阻断，S2）",
      not any(i["severity"] in ("critical", "high") for i in back),
      [i["severity"] for i in back])
check("L2 finding 不带 redline", not any(i["redline"] for i in back))
trusted = sarif_io.from_sarif(doc, trusted=True)
check("--sarif-trusted 时恢复原档（S2 的唯一例外）",
      [i["severity"] for i in trusted] == ["critical", "medium"],
      [i["severity"] for i in trusted])
# 封顶的边界：低档工具报的东西也不该被抬到 medium 以上
mid = sarif_io.from_sarif({"version": "2.1.0", "runs": [{"results": [
    {"ruleId": "X", "level": "note", "message": {"text": "t"}}]}]})
check("L2 note 仍是 low（不因封顶而被抬高）", mid[0]["severity"] == "low", mid[0]["severity"])

print("=== 2b. sarif_io：畸形输入 ===")
check("空 dict → []", sarif_io.from_sarif({}) == [])
check("非 SARIF → []", sarif_io.from_sarif({"hello": 1}) == [])
check("runs 非 list 不炸", sarif_io.from_sarif({"version": "2.1.0", "runs": "x"}) == [])
check("result 缺 locations 有兜底",
      len(sarif_io.from_sarif({"version": "2.1.0", "runs": [{"results": [{"ruleId": "A"}]}]})) == 1)

print("=== 2c. sarif_io：baseline ===")
tmp = tempfile.mkdtemp(prefix="bl_")
bl = os.path.join(tmp, "baseline.json")
n = sarif_io.save_baseline(bl, issues, verdict="BLOCKED")
# 指纹不再含行号（M1）：行号平移不应让基线失效。但同文件同规则的
# 多条命中靠 occurrence 区分，不能被折叠掉——那是漏报。
fp0 = sarif_io.issue_fingerprint(dict(issues[0], occurrence=0))
fp1 = sarif_io.issue_fingerprint(dict(issues[1], occurrence=0))
check("save 写入 2 条指纹", n == 2)
loaded, note = sarif_io.load_baseline(bl)
check("基线 schema 记为 2", json.load(open(bl, encoding="utf-8"))["schema"] == 2)
check("新基线无失效提示", note == "", note)
kept, suppressed = sarif_io.apply_baseline(list(issues), loaded)
check("全部命中基线时 kept 为空", kept == [], kept)
check("被抑制项转 info 且带指纹",
      len(suppressed) == 2 and all(s["severity"] == "info" for s in suppressed)
      and {s["fingerprint"] for s in suppressed} == set(loaded),
      # 不假设 suppressed 的顺序：assign_occurrences 按 (file, rule_id, line) 排序分配
      # occurrence，写入顺序与原列表不一定一致
      [(s["fingerprint"], s["file"]) for s in suppressed])
kept2, _ = sarif_io.apply_baseline(list(issues), {"deadbeefdeadbeef"})
check("未命中基线时原样返回", len(kept2) == 2)
check("基线文件不存在返回空且不炸",
      sarif_io.load_baseline(os.path.join(tmp, "none.json")) == (set(), ""))
with open(bl, "w", encoding="utf-8") as f:
    f.write('{"fingerprints": ["不是指纹", "0123456789abcdef"]}')
check("只认真指纹格式", sarif_io.load_baseline(bl)[0] == {"0123456789abcdef"})
# 旧版 schema（指纹含行号）应失配并给提示，而不是静默失效
with open(bl, "w", encoding="utf-8") as f:
    json.dump({"schema": 1, "fingerprints": ["0123456789abcdef"]}, f)
_loaded_old, note_old = sarif_io.load_baseline(bl)
check("旧版基线提示重建", "旧版 schema" in note_old and "--write-baseline" in note_old, note_old)
dup_in_same_file = issues + [dict(issues[0])]
kept_same, dropped_same = sarif_io.dedupe(dup_in_same_file)
# dedupe 判据是「身份键 + 行号」：重复项与原项 line 完全相同，故被折叠；
# 若行号不同（如同文件两处未钉版）则三条都保留。两种情形的专项断言见 _test_p17_verify.py
check("dedupe 折叠完全同一条（同 file+rule+line）",
      len(kept_same) == 2 and len(dropped_same) == 1,
      (len(kept_same), len(dropped_same)))
# dedupe 的真正用武之地是跨工具：L2 报同一位置同一规则时应收敛成一条
cross_tool = [
    {"rule_id": "FORB-001", "file": "a.md", "line": 3, "title": "FORB-001", "source": None},
    {"rule_id": "FORB-001", "file": "a.md", "line": 3, "title": "FORB-001", "source": "l2"},
]
kept_x, dropped_x = sarif_io.dedupe(cross_tool)
check("dedupe 仍是「折叠完全同一条」（跨工具场景）",
      len(dropped_x) == 1, (len(kept_x), len(dropped_x)))

print("=== 2d. M1：指纹抗行号漂移，但同规则多处命中不能被折叠 ===")
fp_line10 = sarif_io.fingerprint("DEP-PIN-001", "requirements.txt", line=10, title="")
fp_line11 = sarif_io.fingerprint("DEP-PIN-001", "requirements.txt", line=11, title="")
check("行号变化不影响指纹（M1）", fp_line10 == fp_line11, (fp_line10, fp_line11))
multi = [
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 10, "found": "a"},
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 11, "found": "b"},
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 12, "found": "c"},
]
kept_m, dropped_m = sarif_io.dedupe([dict(x) for x in multi])
check("同文件同规则 3 条命中不被折叠（防漏报）",
      len(kept_m) == 3 and not dropped_m, (len(kept_m), len(dropped_m)))
shifted = [
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 11, "found": "a"},
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 12, "found": "b"},
    {"rule_id": "DEP-PIN-001", "file": "requirements.txt", "line": 13, "found": "c"},
]
sarif_io.assign_occurrences(shifted)
bl_multi = {sarif_io.issue_fingerprint(x, x.get("occurrence")) for x in shifted}
kept_s, _ = sarif_io.apply_baseline([dict(x) for x in shifted], bl_multi)
check("行号整体平移后基线仍全命中（M1 的实际价值）", kept_s == [], kept_s)

print("=== 3. config_loader：只许更严 ===")
import copy
BASE_SPEC = {
    "bundle": {"max_file_count": 1000, "warn_file_count": 100,
                "max_total_bytes": 52428800, "warn_total_bytes": 10485760},
    "frontmatter": {"required": ["slug", "version", "displayName"],
                    "slug_pattern": "^[a-z0-9]+(-[a-z0-9]+)*$",
                    r"semver_pattern": r"^\d+\.\d+\.\d+",
                    "slug_min": 2, "slug_max": 128},
    "forbidden_files": [".gitignore"],
    "forbidden_globs": ["*.pyc", "*.class"],
    "version_locations": ["SKILL.md", "config.json"],
    "github_allowed_files": ["LICENSE"],
}
BASE_RULES = [{"id": "FM-001", "severity": "critical", "patterns": ["x"]}]
# apply_config 是就地修改（gate.py 传的就是真对象），所以每次用深拷贝隔离，
# 否则浅拷贝会让嵌套 dict 共享，测出来的「生效」分不清是真的还是串味
spec, rules = copy.deepcopy(BASE_SPEC), copy.deepcopy(BASE_RULES)
applied, wl = config_loader.apply_config(
    spec, rules,
    {"spec": {"bundle": {"max_file_count": 500}},
     "forbidden_files_append": [".env"],
     "rules_append": [{"id": "MY-001", "severity": "medium", "patterns": ["abc"]}],
     "whitelist_append": ["示例"]})
check("阈值调低生效", spec["bundle"]["max_file_count"] == 500)
check("封禁文件只增", ".env" in spec["forbidden_files"] and len(spec["forbidden_files"]) == 2)
check("规则追加生效", [r["id"] for r in rules] == ["FM-001", "MY-001"])
check("摘要三条齐全", len(applied) == 3, applied)
check("白名单返回内容而非摘要", wl == ["示例"], wl)
check("未提及字段保持原样", spec["frontmatter"]["required"] == ["slug", "version", "displayName"]
      and spec["bundle"]["warn_file_count"] == 100)

for name, bad_cfg, expect in [
    ("阈值调高被拒", {"spec": {"bundle": {"max_file_count": 9999}}}, "只能调低"),
    ("未知 spec 段落被拒", {"spec": {"nope": {}}}, "不存在的段落"),
    ("未知字段被拒", {"spec": {"bundle": {"nope": 1}}}, "没有可覆盖的字段"),
    ("重复规则 ID 被拒", {"rules_append": [{"id": "FM-001", "patterns": ["x"]}]}, "重复"),
    ("非法正则被拒", {"rules_append": [{"id": "Z", "patterns": ["("]}]}, "合法正则"),
    ("无 patterns 被拒", {"rules_append": [{"id": "Z"}]}, "patterns"),
]:
    try:
        config_loader.apply_config(copy.deepcopy(BASE_SPEC), copy.deepcopy(BASE_RULES), bad_cfg)
        check(name, False, "居然通过了")
    except config_loader.ConfigError as e:
        check(name, expect in str(e), str(e)[:90])

try:
    config_loader.apply_config(copy.deepcopy(BASE_SPEC), copy.deepcopy(BASE_RULES),
                               {"spec": {"bundle": {"max_file_count": 500}}}, strict=True)
    check("--strict 拒绝 spec 覆盖", False, "居然通过了")
except config_loader.ConfigError as e:
    check("--strict 拒绝 spec 覆盖", "--strict" in str(e))

# v2.1.1：--strict 现在拒绝全部四类覆盖键（含追加类）。
# 原先只拦 spec / forbidden_files_append，rules_append 与 whitelist_append 放行，
# 于是「--strict 锁死规则库」却仍能用白名单静音 RED-NET-* 红线（对抗式审查 S3）。
for name, cfg, expect in [
    ("--strict 拒绝 rules_append", {"rules_append": [{"id": "OK-1", "patterns": ["z"]}]}, "--strict"),
    ("--strict 拒绝 whitelist_append", {"whitelist_append": ["翻墙"]}, "--strict"),
    ("--strict 拒绝 forbidden_files_append", {"forbidden_files_append": [".x"]}, "--strict"),
]:
    try:
        config_loader.apply_config(copy.deepcopy(BASE_SPEC), copy.deepcopy(BASE_RULES), cfg, strict=True)
        check(name, False, "居然通过了")
    except config_loader.ConfigError as e:
        check(name, expect in str(e), str(e)[:90])
applied_s, _ = config_loader.apply_config(copy.deepcopy(BASE_SPEC), copy.deepcopy(BASE_RULES),
                                          {"rules_append": [{"id": "OK-1", "patterns": ["z"]}]})
check("非 strict 下追加规则仍可用", len(applied_s) == 1)

print("=== 3c. P0-1 对抗断言：配置不得放宽平台硬校验（阻断 B1）===")
# 这组是回归防线：v2.1.0 曾被一个 6 行配置把 BLOCKED 变成 PASS。
# 任何人日后改 FIELD_POLICY，必须先让这几条红掉。
P0_ATTACKS = [
    ("frontmatter.required 清空", {"spec": {"frontmatter": {"required": []}}}, "禁止覆盖"),
    ("frontmatter.required 缩减", {"spec": {"frontmatter": {"required": ["slug"]}}}, "禁止覆盖"),
    ("slug_pattern 放宽为 .*", {"spec": {"frontmatter": {"slug_pattern": ".*"}}}, "禁止覆盖"),
    ("slug_min 放宽到 0", {"spec": {"frontmatter": {"slug_min": 0}}}, "禁止覆盖"),
    ("semver_pattern 覆盖", {"spec": {"frontmatter": {"semver_pattern": ".*"}}}, "禁止覆盖"),
    ("forbidden_files 缩减", {"spec": {"forbidden_files": []}}, "顶层列表字段"),
    ("forbidden_globs 缩减", {"spec": {"forbidden_globs": []}}, "顶层列表字段"),
    ("version_locations 缩减", {"spec": {"version_locations": ["SKILL.md"]}}, "顶层列表字段"),
]
for name, cfg, expect in P0_ATTACKS:
    s = copy.deepcopy(BASE_SPEC)
    try:
        config_loader.apply_config(s, [], cfg)
        check(name + " 被拒", False, f"居然通过了 -> {s}")
    except config_loader.ConfigError as e:
        check(name + " 被拒", expect in str(e), str(e)[:80])

# 未登记字段必须 fail-closed（防止「作者忘了登记」变成绕过口）
s = copy.deepcopy(BASE_SPEC)
s["bundle"]["brand_new_knob"] = 1
try:
    config_loader.apply_config(s, [], {"spec": {"bundle": {"brand_new_knob": 2}}})
    check("未登记字段 fail-closed", False, "居然通过了")
except config_loader.ConfigError as e:
    check("未登记字段 fail-closed", "未登记覆盖策略" in str(e), str(e)[:80])

# 正例：允许的方向必须仍然可用（别把门禁焊死）
s = copy.deepcopy(BASE_SPEC)
ok, _ = config_loader.apply_config(s, [], {
    "spec": {"bundle": {"max_file_count": 500}},                    # 阈值调低
    "forbidden_files_append": [".env", ".secrets"],                # 专用追加键
})
check("正例：调低阈值 + 追加封禁项仍生效",
      s["bundle"]["max_file_count"] == 500 and ".env" in s["forbidden_files"],
      s["bundle"]["max_file_count"])
check("正例：追加是幂等的（重复加同一项不重复）",
      config_loader.apply_config(s, [], {"forbidden_files_append": [".env"]})[0] == []
      and s["forbidden_files"].count(".env") == 1, s["forbidden_files"])

print("=== 3d. P0-3 对抗断言：矛盾规则与危险正则（阻断 S4/S5）===")
for name, rule, expect in [
    ("level=info 的规则被拒", {"id": "E1", "severity": "critical", "level": "info", "patterns": ["x"]}, "不允许 level=info"),
    ("ReDoS 嵌套量词被拒", {"id": "E2", "severity": "low", "patterns": ["(a+)+b"]}, "ReDoS"),
    ("过长 pattern 被拒", {"id": "E3", "severity": "low", "patterns": ["x" * 300]}, "过长"),
    ("pattern 非字符串被拒", {"id": "E4", "severity": "low", "patterns": [123]}, "必须是字符串"),
    ("patterns 非列表被拒", {"id": "E5", "severity": "low", "patterns": "x"}, "必须是列表"),
    ("pattern 条数超限被拒", {"id": "E6", "severity": "low", "patterns": ["x"] * 21}, "超过上限"),
]:
    try:
        config_loader.apply_config({}, [], {"rules_append": [rule]})
        check(name, False, "居然通过了")
    except config_loader.ConfigError as e:
        check(name, expect in str(e), str(e)[:90])

for name, wl, expect in [
    ("白名单条数超限被拒", ["p%d" % i for i in range(21)], "超过上限"),
    ("白名单过长被拒", ["x" * 300], "过长"),
]:
    try:
        config_loader.apply_config({}, [], {"whitelist_append": wl})
        check(name, False, "居然通过了")
    except config_loader.ConfigError as e:
        check(name, expect in str(e), str(e)[:90])

# 正例：普通自定义规则仍可用
r = []
config_loader.apply_config({}, r, {"rules_append": [
    {"id": "GOOD-1", "severity": "medium", "category": "SPEC", "patterns": ["正常规则"]}]})
check("正例：普通自定义规则可用", [x["id"] for x in r] == ["GOOD-1"])

print("=== 3b. config_loader：文件读取 ===")
cfg_path = os.path.join(tmp, "c.json")
with open(cfg_path, "w", encoding="utf-8") as f:
    json.dump({"platform": "github"}, f)
check("JSON 读取（platform）", config_loader.load_config(cfg_path)["platform"] == "github")

print()
print("=" * 60)
print(f"失败 {len(fails)} 项" if fails else "全部通过 ✅")
for f in fails:
    print("  -", f)
sys.exit(1 if fails else 0)
