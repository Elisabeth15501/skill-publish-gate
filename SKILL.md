---
name: skill-publish-gate
slug: skill-publish-gate
version: 2.2.1
displayName: Skill 发布门禁（代码安全 + 平台规范）
summary: 发布 Skill 前本地跑一遍，一次看全「代码安全」与「SkillHub/ClawHub/ima 平台规范」，命中即阻断
tags: [skill, 发布门禁, 合规预检, 代码安全, preflight, 上架检查, skillhub, clawhub, ima, sarif, publish-gate]
license: MIT-0
description: >-
  Skill 发布门禁（preflight gate）——把「代码安全」与「平台规范」收成一道本地检查。
  前称 skillhub-gate（v1.x  lineage 沿用于此），2026-10 起统一以 skill-publish-gate 为名；
  按旧名 @skill:skillhub-gate 或搜索 skillhub-gate 引用的，均已迁移到本名，功能与 CLI 完全不变。
  两件事一起看：① 代码安全：疑似凭据泄漏、恶意执行模式、Prompt 注入、持久化文件篡改、身份证/手机/
  银行卡等 PII 泄漏、开源传染性协议与版权剥离；② 平台规范：frontmatter 硬校验（slug/version/
  displayName 缺失或非 SemVer、YAML 静默解析失败）、封禁文件与超大产物包（.gitignore/.nojekyll/
  LICENSE/__pycache__/*.pyc/.github 会令正式发布报 400，文件数 >1000 会卡死）、发布产物卫生
  （.github_token/.workbuddy/.env/.venv/node_modules 不得进包）、包体阈值、版本一致性、权限声明缺失。
  内容合规红线（网络规避敏感词族、规避类功能叙事、广告法绝对化用语、需资质的金融类表述）一并覆盖，
  词表合并自 ai-weekly 2026-09-22 文档措辞下架事故的固化经验，并支持把发布后平台审核的新发现
  用 --learn 回灌进规则集。支持 --platform skillhub | github | clawhub 切换口径：ClawHub 接受任意
  扩展名、内容词族降级为 WARN、额外校验 MIT-0 授权与 requires 声明一致性；github 模式豁免开源
  许可文件。检测纯本地正则 + 轻量 AST 兜底，零出网、零必需密钥。退出码 0=PASS / 2=NEEDS_FIX /
  1=BLOCKED，可直接当 CI gate 或 pre-publish hook 使用。
use_when:
  - 准备 `skillhub publish` / `clawhub push` 之前想先本地预检，避免被服务端拒或卡死
  - 想一次看清一个 skill 的代码安全风险（凭据 / 注入 / 恶意模式 / PII / 协议传染）
  - 检查 SKILL.md frontmatter 是否会被平台 CLI 静默解析失败
  - 批量体检多个待发布 skill（本地技能库、CI 矩阵）
  - 想确认文档措辞是否踩了内容审核红线（网络规避词族、绝对化用语、金融敏感表述）
  - 以前用过 skillhub-gate / ai-weekly-publish-gate，现在要找同一个门禁的新名字
trigger_keywords:
  - skill 门禁
  - 发布前检查
  - 发布预检
  - 上架前检查
  - 代码安全扫描
  - skill sec gate
  - skillhub gate（历史名）
  - clawhub gate
  - publish gate
  - skill publish gate
  - preflight
  - 发布门禁
environment: local
network: none
dependencies: PyYAML（python -m pip install pyyaml；脚本缺失时自动尝试安装）
disclaimer: 本门禁仅做本地规范预检与静态安全扫描，不构成任何平台的上架保证。最终能否发布成功由各平台审核决定，责任由开发者自行承担。
---

# Skill 发布门禁（skill-publish-gate）

## 0.1 更名说明：skillhub-gate → skill-publish-gate

2026-10 由 `skillhub-gate` 更名为 `skill-publish-gate`。**不是新起点，是同一个东西改名**：
代码、CLI、退出码、规则库、tag 序列全部不变，`v1.0.0`~`v1.4.0` 仍是同一条提交线的历史。

| 旧 | 新 | 影响 |
|---|---|---|
| `@skill:skillhub-gate` | `@skill:skill-publish-gate` | 需改调用点（AI 侧引用名） |
| 目录 `~/.workbuddy/skills/skillhub-gate` | `.../skill-publish-gate` | 路径本身，无影响 |
| `skillhub install skillhub-gate` | `skillhub install skill-publish-gate` | 平台侧按 slug 安装时改 |
| `python gate.py check ...` | 完全不变 | CLI 未动 |

改名理由：老名字把「SkillHub」这一种平台写进了技能身份，而本门禁同时守 SkillHub 与 ClawHub
两个平台，还带了代码安全一层——旧名会把能力边界讲窄。新名 `skill-publish-gate` 只说职责
（发布门禁），平台agnostic，往后加平台不用再改名。

> 若你在别处看到 `ai-weekly-publish-gate`：它早年已并进来，现为一个重定向壳，能力全部在本门禁内。

## 0. 这是什么：一道门禁，两件事

一个 skill 要发出去，发布前其实有**两件互不相干的事**各自都要过：

| 维度 | 原本散在哪 | 漏掉的后果 |
|---|---|---|
| **平台规范** | 平台 CLI 的硬校验、封禁文件、包体上限、声明一致性 | 正式发布才报 400，或包体过大把服务端卡死 |
| **代码安全** | CodeQL / Semgrep / gitleaks，或压根没人查 | 凭据进包、恶意执行模式、Prompt 注入、PII 泄漏 |
| **内容措辞** | 往往只有发布后等平台打回才知道 | ai-weekly 2026-09-22 因一句措辞被判内容审核不通过、整技能下架 |

前两件事在 v1.x 已在本门禁内；第三件事原本挂在 **ai-weekly-publish-gate**（指向外部仓库的
`compliance_check.py`，脚本并不随技能分发）。**v2.0.0 起把这三件事合并成一道门禁**，
词表、叙事正则、回灌闭环全部落到本技能的 `rules/skillhub-spec.json` 里，不再依赖任何外部仓库。

> 已经安装过的 `ai-weekly-publish-gate` 仍在目录里，但已改为重定向说明，能力统一走本门禁。

## 它解决什么

`skillhub publish` 几个让人头疼的特性（已在 skillhub-publish 技能里反复验证）：

- `--dry-run` **只校验 frontmatter**，封禁文件类型要等正式发布才报 400；
- 仓库目录混入测试产物（allure-results / .pytest_cache / data / .venv / node_modules）会让
  发布包上万 part，服务端处理时**卡死无输出**；
- 内容审核是三线并行（内容合规过滤 + 深度漏洞扫描 + 模型安全评估），文档里的网络规避词族、
  绝对化用语、金融敏感表述会直接拒或下架；
- 安全侧：凭据、注入、PII 这些在发布前通常没人查，等平台安全扫描打回时已经下架了。

本门禁把这些**发布前就该发现的问题**一次性本地跑出来，并给 PASS / NEEDS_FIX / BLOCKED 三档结论
+ 退出码，能直接接 CI 或发布脚本。

## 适用范围与边界

**适合用本门禁**：任何准备发布的本地 skill 目录（单技能 `check` / 批量 `dirs`），无论目标是
SkillHub、ClawHub、腾讯 ima 还是先开源到 GitHub。

**不适用 / 容易误用的场景**（别硬套）：

- **运行时监控**：本门禁只做发布前静态预检，不监控已上架 skill 的线上行为。
- **深度应用漏洞审计**（SQLi / XSS / 依赖 CVE / 污点分析）：那是 CodeQL、Semgrep、domsec、
  Codex Security 的职责。本门禁是**发布包级别的轻量体检**，刻意不做工业级深层分析——
  它要的是「发布前 5 秒看出会不会被拒/下架」，不是把代码审穿。
  但 v2.1.0 起这层**可以缝进来**：`--sarif-in` 吃外部 SARIF、`--deep-scan` 直接调外部扫描器，
  结果并入同一个 verdict（**L2 档位封顶 medium，不阻断**）。也就是说「谁做深度分析」可以换，「谁来判能不能发」
  不换。
- **国内监管合规审计报告**（金融/广告法/隐私法律依据文书）：那是 `skill-compliance-check` 的职责。
- **把门禁结论当审核保证**：最终能否上架由各平台审核决定（见底部免责声明）。

## 检查全景

### 代码安全（SECURITY / PRIVACY，跨三平台均为 BLOCKER）

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| SEC-CRED-001 | 疑似 token/key（ghp_/sk-/AKIA/glpat-/xoxb-/AIza 等），命中一律脱敏回显 | BLOCKED |
| SEC-MALWARE-001 | 恶意执行模式（base64 解码后 eval/exec、下载即执行、反向 shell 等） | BLOCKED |
| SEC-PROMPT-001 | Prompt 注入特征（忽略之前指令、越狱、DAN 等） | BLOCKED |
| SEC-PERSIST-001 | 指示宿主永久篡改持久化文件（SOUL.md / MEMORY.md / IDENTITY.md / USER.md） | BLOCKED |
| SEC-LICENSE-001 | 传染性开源协议（copyleft 家族）与版权剥离条款；协议名见规则库，此处不枚举以免自描述误报 | BLOCKED / NEEDS_FIX |
| AST-*-001 | **v2.1.0 新增**：stdlib ast 精确到行的危险调用（动态执行、shell 解释执行、不安全反序列化等；具体函数名见规则库 `AST-*-001`） | BLOCKED |
| PRIV-PATH-001 | 绝对路径泄漏（含本机用户名） | NEEDS_FIX |
| PRIV-NAME-001 | 真实姓名 / 用户名（公开笔名已排除） | NEEDS_FIX |
| PRIV-MEAS-001 | 真实量测值（「整仓 52 个文件」这类暴露仓库规模的表述） | NEEDS_FIX |
| SEC-PERMISSION-001 | 脚本含写文件/子进程/网络但 SKILL.md 无权限声明（对症过度授权） | NEEDS_FIX |

### 平台规范（SPEC，随平台口径变化）

| 检查内容 | 触发后果 |
|---|---|
| FRONTMATTER 合法性：用真 `yaml.safe_load` 解析，抓半角「冒号+空格」等静默失败 | BLOCKED |
| 必填字段：`slug`(kebab-case 2–128) / `version`(SemVer) / `displayName` | BLOCKED |
| 推荐字段：`name` / `description` / `summary` / `tags` | NEEDS_FIX |
| 封禁文件：`.gitignore`/`.nojekyll`/`LICENSE`/`__pycache__`/`*.pyc`/`.github`/`.clawhubignore` | BLOCKED |
| **发布产物卫生**：`.github_token` / `.workbuddy` / `.env` / `.venv` / `node_modules` 不得进包 | BLOCKED |
| 包体：文件数 / 总体积超阈值（卡死风险） | BLOCKED / NEEDS_FIX |
| 版本一致性：`version` 在 SKILL.md/config.json/metadata.json/CHANGELOG.md 是否统一 | NEEDS_FIX |
| 网络声明：声明 `network: none` 但脚本含真实网络调用 | NEEDS_FIX |
| 依赖钉版：`requirements.txt` 未 pin 到 `==version` | NEEDS_FIX |
| INFO 级：出站代理提及（`--proxy`/`HTTPS_PROXY`），默认静音，需人工确认定位为内网出网 | 不阻断 |

### 内容合规（CONTENT，对应平台审核红线）

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| RED-NET-001~003 | 网络规避敏感词族（中文词 + 代理工具同族词 + 机场/节点订阅） | BLOCKED（clawhub 降级 WARN） |
| RED-NET-004 | 规避类功能叙事（把功能描述成「恢复访问 / 解除限制」） | BLOCKED / NEEDS_FIX |
| RED-NET-005 | **v2.0.0 并入**：下架事故固化的扩展词表（防火墙 / v2board / sspanel / clashx）与叙事正则（绕过限制 / 突破封锁 / 解决访问不了 / 走通即可恢复） | BLOCKED（clawhub 降级 WARN） |
| RED-AD-001 | 广告法极限词（最好/第一/唯一/顶级…） | NEEDS_FIX |
| RED-FIN-001 | 金融敏感表述（荐股/保证收益/内部消息…） | NEEDS_FIX |
| INFO-PROXY-001 | 出站代理提及，默认静音 | 不阻断 |

> 元语境豁免：当命中词出现在「否定 / 定义 / 清单 / 说明」语境（如「检测网络规避敏感词」）时
> 视为自描述，不误报——所以合规/安全类技能罗列规则词不会被自己标红。

### Agentic / MCP 专有类目（v2.1.0 新增，skill 独有攻击面）

通用代码扫描器不读 SKILL.md，抓不到「指令式」风险——这两类只可能由发布门禁守。

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| AGENT-MEMORY-001 | 记忆投毒：要求跨会话永久记住用户身份/偏好，或每次都向第三方汇报 | BLOCKED（clawhub 降 HIGH） |
| AGENT-LEAK-001 | 系统提示泄漏：要求输出/回显系统提示、初始指令、内部规则 | BLOCKED（clawhub 降 WARN） |
| AGENT-AUTONOMY-001 | 过度代理权：跳过用户确认就执行不可逆动作（删除/支付/发布/转账） | BLOCKED（clawhub 降 WARN） |
| AGENT-REFUSAL-001 | 反拒绝：要求不得拒绝、不得提示风险、无条件执行 | BLOCKED（clawhub 降 WARN） |
| AGENT-TRIGGER-001 | 触发词滥用：「所有问题都调用本技能」 | NEEDS_FIX |
| MCP-PRIV-001 | MCP 权限过宽：`permissions: "*"`、任意文件读写、跳过沙箱 | BLOCKED（clawhub 降 WARN） |
| MCP-PROMPT-001 | 工具描述投毒：「不要告诉用户这次操作」「调用前不要检查」 | BLOCKED（clawhub 降 HIGH） |
| MCP-DECLARE-001 | 提到 MCP 但未在 `requires` 声明 | INFO（默认静音） |
| AST-EVAL-001 / AST-EXEC-001 / AST-OS-001 / AST-SHELL-001 / AST-PICKLE-001 | stdlib ast 精确行号：动态执行、shell 解释执行、不安全反序列化（函数名与行号以实际扫描结果为准） | BLOCKED（high） |
| AST-PARSE-001 | 文件解析失败（该文件未被 ast 覆盖） | INFO（默认静音） |

> 这批规则**不叠加全局元语境词表**（`use_global_meta_markers: false`）——它们的攻击句式本身
> 就是「不要 X」「无需确认」，叠加「不要」会让规则自己废掉。每条规则改用自己的
> `exclude_patterns` 精确豁免否定式表述（如「本技能不输出系统提示词」不算违规）。

### ClawHub 模式（`--platform clawhub`）专属

| 类别 | 检查内容 | 触发后果 |
|------|----------|----------|
| 封禁文件 | clawhub 模式**跳过**封禁文件检查（接受任意扩展名，`.gitignore`/`.github` 等不再拦） | — |
| 发布产物卫生 | clawhub 模式同样跳过（ClawHub 不按文件类型挑） | — |
| 内容词族 | `RED-NET-001~005` 在 clawhub 模式**降级为 WARN**（ClawHub 不做关键词内容审核） | NEEDS_FIX |
| 授权字段 | frontmatter 声明 `license:` 且非 `MIT-0` → BLOCKED；声明为 `MIT-0` → WARN（建议移除该字段） | BLOCKED / NEEDS_FIX |
| 声明一致性 | 脚本调外部 CLI/子进程/网络但 frontmatter 未声明 `requires` → WARN | NEEDS_FIX |

> 注：安全类检查（凭据 / 恶意代码 / Prompt 注入 / 持久化篡改 / 协议传染）在三种平台模式下
> **均为 BLOCKER**，是各平台安全扫描的本地映射，不随平台降级。

### ima 模式（`--platform ima`）专属

腾讯 ima 知识库的包口径与 SkillHub 有四处不同，单独一档（规则见 `platform_profiles.ima`）：

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| IMA-FM-001 | frontmatter 七字段齐全（`name`/`displayName`/`description`/`version`/`trigger_keywords`/`reference`/`disclaimer`） | BLOCKED |
| IMA-FILE-001 | 包内含平台生成物 `_meta.json` | BLOCKED |
| IMA-QUOTE-001 | 字符串用了全角引号 `“”‘’`（ima 只认 ASCII 直引号） | NEEDS_FIX |
| IMA-NAME-001 | 文件名含非 ASCII 字符 | NEEDS_FIX |
| IMA-TRIGGER-001 | `trigger_keywords` 超过 5 条 | NEEDS_FIX |

> 该 profile 的字段清单来自 v2 方案的复盘记录。**若平台口径与此处不符，改
> `rules/skillhub-spec.json` 的 `platform_profiles.ima` 一段即可，不涉及 `gate.py`。**

### 缝接层（v2.1.0 新增，全部可选、默认关闭）

本门禁只判「能不能发布」，不重复造通用代码审计。深度结果通过三个入口并入同一个 verdict：

```bash
# ① 产出 SARIF 2.1.0（喂 GitHub Code Scanning / 任意 SARIF 消费方）
python scripts/gate.py check --dir <skill目录> --format sarif -o gate.sarif

# ② 导入外部扫描器的 SARIF（domsec / SkillSpector / Codex Security 都吃）
python scripts/gate.py check --dir <skill目录> --sarif-in domsec.sarif
#   外部 finding 档位封顶 medium（error→medium、warning→low），且一律不带 redline，
#   所以 L2 永远不能单独把一个 skill 判成 BLOCKED；
#   已过验证层的工具可加 --sarif-trusted 恢复原始档位

# ③ 直接调外部扫描器（不经 shell，失败不影响 L0 判定）
python scripts/gate.py check --dir <skill目录> \
    --deep-scan "python3 ~/tools/scanner.py --format sarif {dir}"
#   {dir} 会被替换为目标目录；路径含空格时必须加引号
#   --offline 是硬开关：与 --deep-scan 互斥，防止 CI 手滑把源码传给外部服务

# ④ 基线：抑制「确认过的误报」（指纹 = sha256(ruleId|file|line|title) 前 16 位）
python scripts/gate.py check --dir <skill目录> --write-baseline ./baseline.json
python scripts/gate.py check --dir <skill目录> --baseline ./baseline.json
#   被基线抑制的项不删除，降为 info 保留可追溯——「当初为什么放过它」必须查得到

# ⑤ 外部配置：阈值 / 封禁文件追加 / 自定义规则（只许更严）
python scripts/gate.py check --dir <skill目录> --config ./gate.json
python scripts/gate.py check --dir <skill目录> --config ./gate.json --strict  # 锁死内置规则库
```

**配置只能让门禁更严，不能更松**：阈值只许调低、红线规则不可被覆盖或降级、`--strict` 下
任何覆盖直接报错（仅允许追加类）。理由是发布门禁的定位——它不该因为一个配置文件而失守。

## 执行逻辑

触发后调用 `scripts/gate.py`：

```bash
# 单技能门禁（默认 skillhub 模式；退出码 0/2/1）
python scripts/gate.py check --dir <skill目录>
# 机器可读
python scripts/gate.py check --dir <skill目录> --json
# 输出到文件
python scripts/gate.py check --dir <skill目录> --output gate-report.txt
# 批量汇总
python scripts/gate.py dirs --dir ~/.workbuddy/skills
# 显示 INFO 级命中（出站代理等，默认静音，需人工确认定位）
python scripts/gate.py check --dir <skill目录> --show-info
# 强制扫全目录（默认若目录自身是 git 仓库则只扫 git 跟踪集，等价发布所见）
python scripts/gate.py check --dir <skill目录> --all-files
# ClawHub 预检（任意扩展名 + 内容词族降级 + MIT-0/requires 一致性检查）
python scripts/gate.py check --dir <skill目录> --platform clawhub
# GitHub 开源预检（豁免 LICENSE / .github / .gitignore）
python scripts/gate.py check --dir <skill目录> --platform github
# ima 预检（七字段 / 零 _meta.json / ASCII 引号 / 纯 ASCII 文件名 / 触发词 ≤5）
python scripts/gate.py check --dir <skill目录> --platform ima
# SARIF 产出与导入（缝接层，详见「缝接层」一节）
python scripts/gate.py check --dir <skill目录> --format sarif -o gate.sarif
python scripts/gate.py check --dir <skill目录> --sarif-in external.sarif
# 回灌：发布后审核发现的新坑写回 rules/feedback.json（防复发核心）
python scripts/gate.py check --dir <skill目录> --learn '{"type":"blocker","pattern":"新危险词","reason":"平台审核打回：..."}'
python scripts/gate.py check --dir <skill目录> --learn '{"type":"whitelist","pattern":"企业内网出站","reason":"已确认定位为内网场景"}'
python scripts/gate.py check --dir <skill目录> --learn '{"type":"warn","pattern":"某弱建议表述","reason":"..."}'
```

### JSON 输出结构（`--format json`）

`--format json` 输出如下字段，可直接喂 CI / 后处理脚本：

```json
{
  "skill": "my-skill",
  "directory": "/abs/path/to/my-skill",
  "platform": "skillhub",
  "spec_version": "2.1.0",
  "config_applied": ["/* 外部配置生效摘要，空数组=未用 --config */"],
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
  "info_hits": [ "/* 同 issues 结构，仅 INFO 级；默认不计入 verdict，--show-info 才展示 */" ]
}
```

- `--output <file>`：把报告写入该文件，**已存在则覆盖**；不指定则只打印到 stdout。
- `issues` 与 `info_hits` 中每条含 `rule_id / category / severity / file / line / found /
  recommendation / redline / authority_type / clause`，便于按规则聚合或定位。

判定与退出码：

- `BLOCKED`（exit 1）：命中 blocker（frontmatter 硬校验失败 / 封禁文件或卫生项 / YAML 解析失败 /
  内容红线 redline / 安全类 BLOCKER）→ **必须修**。
- `NEEDS_FIX`（exit 2）：仅建议项（medium/low）→ 建议修，不阻断。
- `PASS`（exit 0）：无问题 → 可发布。
- **目录合法性**：`--dir` 指向不存在的路径、或不含 `SKILL.md` 的目录时，FRONTMATTER 检查
  会报 `FM-001`（`critical` / BLOCKED，exit 1）——不会静默放行，也不会因缺文件崩溃。

规则数据集中在 `rules/skillhub-spec.json`，新增/调整红线直接改 JSON 即可，不用动脚本
（规则引擎直接把 `patterns` 当正则编译，元语境豁免、平台降级、白名单、回灌都在脚本侧统一处理）。

规则条目可用字段：`id` / `category` / `severity` / `redline` / `level`(info 静音) /
`patterns` / `exclude_patterns` / `self_describing_markers` / `use_global_meta_markers`(默认 true) /
`platform_downgrade` / `scan_targets`(docs|scripts|all) / `clause` / `origin`(来源溯源) /
`description` / `authority_type`。

## 回灌闭环（防复发核心）

发布后若平台审核又暴露新坑，用 `--learn` 把发现写回 `rules/feedback.json`：

- `{"type":"blocker","pattern":"...","reason":"..."}` → 追加为额外 BLOCKER 规则（下次扫描即拦）；
- `{"type":"warn","pattern":"...","reason":"..."}` → 追加为额外建议项；
- `{"type":"whitelist","pattern":"...","reason":"..."}` → 加入白名单，命中即静音（只静音你确认过的
  误报，绝不哑掉真问题）。

下次扫描自动加载：`learned_blockers`/`learned_warns` 作为增量规则，`whitelist` 命中即跳过。
**私有白名单 = 只静音确认的误报**，不污染默认规则库，也不会哑掉真实红线。
这是把「一次下架教训」固化为「下次自动防复发」的关键机制（机制原型来自 ai-weekly 被下架的事故）。

## 三条铁律（踩过的坑）

1. **「功能合法」≠「文档合规」**：技能功能可能完全合法，但一句「提升海外源可达性」就会被判违规。
   文档里绝不出现法律含义明确的敏感词，更不把功能描述成「解决某类访问限制」。
2. **`--proxy` 的正确写法**：定位为「企业内网要求所有出站流量经统一代理」的通用 HTTP 参数，
   明写「仅用于合法的企业内网出站场景，不提供也不支持任何规避网络管理措施的能力」。
3. **降级而非绕行**：外部源不可达时，既定行为是降级到国内源 + 离线快照 + 如实标注，
   而不是「配代理恢复访问」。

## 发布前自检清单（给本技能自己）

1. `python scripts/gate.py check --dir .`（默认 skillhub 模式）应为 BLOCKED（本仓库含
   `.github`/`.gitignore`，属 SkillHub 发布需排除项，预期）；
   `--platform github` 应为 PASS；`--platform clawhub` 预期 NEEDS_FIX（本技能 frontmatter 含
   `license: MIT-0` 触发 `LICENSE-FIELD-001` WARN、脚本用 `subprocess` 未声明 `requires`
   触发 `META-MISMATCH-001` WARN，均属预期，不阻断）。
2. 用 `git archive HEAD` 导出干净副本再发布，别 `publish .` 仓库目录；
3. 不写 `license:` 字段（避免踩 ClawHub 强制 MIT-0 的明文禁令，跨平台各出副本）。

## 与其他工具的分工

| 工具 | 主场 | 与本门禁 |
|---|---|---|
| **skill-publish-gate（本）** | 发布包门禁：包内容 + 结构 + 措辞 + 轻量安全 | — |
| `skill-compliance-check` | 国内监管合规（金融/广告法/隐私法律依据） | 本门禁管「能不能发」，它管「发上去合不合规」 |
| CodeQL / Semgrep / domsec | 工业级源码漏洞分析（AST/污点/CVE） | 本门禁是发布前快检，深层审计走它们 |
| gitleaks | 专用密钥泄漏扫描 | 本门禁只做包内凭据形态粗检，CI 里可再叠 gitleaks |
| 平台安全扫描 | VirusTotal / LLM 评估 / 模型安全 | 本门禁是它们的本地预演 |

## 免责声明

本门禁仅做本地规范预检与静态安全扫描，**不构成任何平台的上架保证**。SkillHub 为三线并行审核
（内容合规过滤 + 深度漏洞扫描 + 模型安全评估），ClawHub 为「安全扫描 + 强制 MIT-0 + 声明一致性」，
这些判定由平台侧做出。最终能否上架由平台审核决定，责任由开发者自行承担。
