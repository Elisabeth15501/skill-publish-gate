# CLI 参数全表（按需查阅，勿预先读入）

> SKILL.md §1 只给最小可用命令；这里是全部开关。参数有疑问或需要组合使用时查这里。

## 子命令

| 子命令 | 用途 |
|--------|------|
| `check` | 对单个 skill 目录做门禁（默认） |
| `dirs` | 批量检查多个 skill 并汇总（默认平台是 `github`，注意与 `check` 不同） |

## check 常用

```bash
python scripts/gate.py check --dir <skill目录>              # 默认 skillhub 口径
python scripts/gate.py check --dir <skill目录> --format json  # 机器可读
python scripts/gate.py check --dir <skill目录> -o report.txt # 写文件（已存在则覆盖）
python scripts/gate.py dirs --dir ~/.workbuddy/skills        # 批量
```

## 口径与范围

| 参数 | 说明 |
|------|------|
| `--platform` | `skillhub`（默认）/ `github` / `clawhub` / `ima`。**非法值 exit 2**，不会静默按默认口径跑完 |
| `--all-files` | 强制扫全目录。默认若目录自身是 git 仓库则只扫 git 跟踪集（等价 CI / 发布所见） |
| `--show-info` | 展示 INFO 级命中（出站代理等）。默认静音 |

优先级：命令行 `--platform` > `--config` 里的 `platform` > 默认 `skillhub`。

## 缝接层（全部可选、默认关闭）

深度审计不是本门禁的职责，但**可以缝进来**——「谁做深度分析」可以换，「谁来判能不能发」不换。

```bash
# ① 产出 SARIF 2.1.0（喂 GitHub Code Scanning 或任意 SARIF 消费方）
python scripts/gate.py check --dir <skill目录> --format sarif -o gate.sarif

# ② 导入外部扫描器的 SARIF（domsec / SkillSpector / Codex Security 都吃）
python scripts/gate.py check --dir <skill目录> --sarif-in domsec.sarif

# ③ 直接调外部扫描器（不经 shell；失败不影响本地判定）
python scripts/gate.py check --dir <skill目录> \
    --deep-scan "python3 ~/tools/scanner.py --format sarif {dir}"
```

缝接层三条不变量：

1. **外部 finding 档位封顶 medium**（error→medium、warning→low），且一律不带 redline，
   所以 **L2 永远不能单独把一个 skill 判成 BLOCKED**。已过验证层的工具加
   `--sarif-trusted` 恢复原始档位——这是唯一例外。
2. **深度层失败绝不影响本地判定**。扫描器挂掉、超时、输出不合法，都只记一条日志。
3. `--offline` 是硬开关，与 `--deep-scan` 互斥。理由是 Codex Security 必须登录、
   domsec 要把源码传给第三方——而本门禁的存在理由之一就是「一个字节都不外传」，
   那就该做成开关而不是文档承诺。

`--deep-scan` 的 `{dir}` 会被替换成目标目录。**路径含空格时必须给整条命令加引号**，
且命令里的路径也要各自加引号（如 `"C:/Program Files/x.py"`）。不经 shell，所以 `;` `&&`
不会被当命令分隔符。

## 基线

```bash
python scripts/gate.py check --dir <skill目录> --write-baseline ./baseline.json
python scripts/gate.py check --dir <skill目录> --baseline ./baseline.json
```

- 指纹 = `sha256(原始ruleId | file | occurrence | title)` 前 16 位，**不含行号**——
  在文件开头加一行注释不会让整份基线失效。
- `occurrence` 是「同一 文件+规则 下的第几次命中」，用来区分同规则的多处命中
  （如 requirements.txt 三行都没钉版是三条问题，不是三条重复）。
- **blocker 不进基线**：`--write-baseline` 跳过 critical/high 与 redline，并在基线文件里
  写 `skipped_blockers` 字段自证当时跳过了什么。
- `--baseline X --write-baseline X` **同开会 exit 2**：语义上「用它筛」与「重新定义它」
  不能共存。
- 被抑制的项不删除，降为 info 保留可追溯——「当初为什么放过它」必须查得到。

## 外部配置

```bash
python scripts/gate.py check --dir <skill目录> --config ./gate.json
python scripts/gate.py check --dir <skill目录> --config ./gate.json --strict
```

配置**只能让门禁更严**：

| 字段 | 允许方向 |
|------|----------|
| `spec.bundle.max_file_count` / `warn_*` / `max_total_bytes` | 只许调低 |
| `spec.frontmatter.*`（`required` / `slug_pattern` / `semver_pattern` / `slug_min` / `slug_max`） | 全锁，禁止覆盖 |
| 未登记的 spec 字段 | 一律拒绝（fail-closed，防「作者忘了登记」变成绕过口） |
| `forbidden_files_append` / `forbidden_globs_append` | 只许追加 |
| `rules_append` | 只许追加；禁止 `level: info`（info 不计入 verdict = 万能静音钥匙）；pattern 有长度与条数上限，且检测嵌套量词（ReDoS） |
| `whitelist_append` | 最多 20 条、单条 ≤200 字符；**对所有规则生效，包括红线** |
| `--strict` | 拒绝全部四类覆盖键 |

顶层清单字段（`forbidden_files` 等）不是段落，不能用 `spec` 覆盖，请改用对应的 `*_append` 键。

## 回灌闭环

发布后若平台审核又暴露新坑，用 `--learn` 写回 `rules/feedback.json`：

```bash
--learn '{"type":"blocker","pattern":"新危险词","reason":"平台审核打回：..."}'
--learn '{"type":"warn","pattern":"某弱建议表述","reason":"..."}'
--learn '{"type":"whitelist","pattern":"企业内网出站","reason":"已确认定位为内网场景"}'
```

下次扫描自动加载。**私有白名单只静音你确认过的误报**，不污染默认规则库，
也不会哑掉真实红线。这是把「一次下架教训」固化为「下次自动防复发」的关键机制。

## JSON 输出结构

```json
{
  "skill": "my-skill",
  "directory": "/abs/path/to/my-skill",
  "platform": "skillhub",
  "spec_version": "2.2.1",
  "config_applied": [],
  "disclaimer": "本门禁仅做本地规范预检，不构成任何平台的上架保证……",
  "verdict": {
    "verdict": "PASS | NEEDS_FIX | BLOCKED",
    "exit_code": 0,
    "total": 0, "blockers": 0, "warnings": 0, "redlines": 0,
    "critical": 0, "high": 0, "medium": 0, "low": 0
  },
  "issues": [
    {
      "rule_id": "FM-001", "category": "SPEC", "severity": "critical",
      "file": "SKILL.md", "line": 1, "found": "SKILL.md 不存在",
      "recommendation": "目标目录必须包含 SKILL.md。",
      "redline": true, "authority_type": "platform_policy",
      "clause": "（可选；仅安全类问题回显协议条款出处）",
      "source": "（可选；l2 = 来自 --sarif-in / --deep-scan 的外部扫描器）"
    }
  ],
  "info_hits": []
}
```

错误信息走 **stderr**，stdout 只有报告本体——所以 `--format json` 可直接 pipe 给下游。

## 性能参考

600 个小文件的 skill 目录约 3 秒（v2.1.1 修掉了三層循环重开文件的 I/O 放大，
此前需 80 秒）。内存峰值约 1.9 MB。
