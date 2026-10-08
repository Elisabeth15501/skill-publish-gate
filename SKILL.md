---
name: skill-publish-gate
slug: skill-publish-gate
version: 3.0.0
displayName: Skill 发布门禁（代码安全 + 平台规范）
summary: 发布 Skill 前本地跑一遍，一次看全「代码安全」与「SkillHub/ClawHub/ima 平台规范」，命中即阻断
tags: [skill, 发布门禁, 合规预检, 代码安全, preflight, 上架检查, skillhub, clawhub, ima, sarif, publish-gate]
license: MIT-0
description: >-
  发布前跑一遍的本地门禁，把「代码安全」与「平台规范」收成一道检查，给 PASS / NEEDS_FIX /
  BLOCKED 三档结论与退出码（0/2/1），可直接当 CI gate 或 pre-publish hook。
  触发场景：即将执行 skillhub publish / clawhub push / 上架腾讯 ima / 开源到 GitHub 之前的预检；
  「这个 skill 能不能发」「会不会被拒」「有没有凭据泄漏或 PII」「文档措辞会不会踩内容审核红线」；
  批量体检本地技能库；frontmatter 是否会被平台 CLI 静默解析失败；以及按旧名 skillhub-gate /
  ai-weekly-publish-gate 找同一道门禁的用户（2026-10 更名，CLI 与退出码不变）。
  覆盖面：凭据/PII/恶意执行/Prompt 注入/持久化篡改/协议传染、frontmatter 硬校验、封禁文件与
  超大产物包、发布产物卫生、版本一致性、依赖钉版、内容审核红线词族、agentic 指令式风险与
  MCP 工具描述投毒。四种口径：--platform skillhub(默认) / github / clawhub / ima。
  NOT for —— 深度应用漏洞审计（SQLi / XSS / 依赖 CVE / 污点分析，交 CodeQL / Semgrep /
  domsec / Codex Security，可用 --sarif-in 或 --deep-scan 把结果缝进来）；国内监管合规文书
  （金融/广告法/隐私法律依据，交 skill-compliance-check）；已上架 skill 的线上监控；
  非 skill 目录的通用代码扫描。检测为纯本地正则 + 轻量 stdlib ast 兜底，零出网、零必需密钥。
when_to_use: >-
  用于「准备发布一个 skill」这个具体时点。需要的是一个本地可跑的判定（能不能发 / 会不会被拒 /
  有没有凭据或 PII），而不是一份安全审计报告或合规法律意见书。不用于深度漏洞分析、
  已发布 skill 的运行期监控、或任何非 skill 目录的通用扫描。
allowed-tools: [Read, Grep, Glob, Bash]
disable-model-invocation: false
user-invocable: true
context: fork
trigger_keywords:
  - skill 门禁
  - 发布预检
  - 上架前检查
  - 代码安全扫描
  - publish gate
  - preflight
environment: local
network: none
dependencies: PyYAML（python -m pip install pyyaml；脚本缺失时自动尝试安装）
permissions: {read: "目标 skill 目录与本技能脚本", write: "rules/feedback.json（仅 --learn 时）、baseline/sarif 输出文件", exec: "python3 scripts/gate.py；--deep-scan 时执行用户显式给出的外部命令", network: "none（--deep-scan 会调用外部扫描器，--offline 可硬关闭）"}
disclaimer: 本门禁仅做本地规范预检与静态安全扫描，不构成任何平台的上架保证。最终能否发布成功由各平台审核决定，责任由开发者自行承担。
---

# Skill 发布门禁（skill-publish-gate）

> **分层说明（渐进式披露）**：本文件只放**每轮都要用**的东西——§0 硬约束、§1 单次执行流程。
> 其余全部在 `references/`，**按需读、不要预先读入**：
> - `references/rule-catalog.md` — 规则全表（每类检查查什么、什么档位、平台差异）
> - `references/cli-reference.md` — CLI 参数全表（缝接层、基线、config、JSON schema）

---

## §0. 硬约束 — 每轮必读，即使上下文被压缩后丢失也要重新遵守

### 0.1 能力边界

- 本门禁只判「这个 skill 能不能发布」，**不重复造通用代码审计**。深度那层用
  `--sarif-in` / `--deep-scan` 缝进来，但**深度层永远不能单独决定能不能发**。
- 结论是**本地预检，不是平台审核保证**。转述给用户时必须带上这个限定，不要说成
  「审核会通过」。
- 前称 `skillhub-gate` / `ai-weekly-publish-gate`，2026-10 统一为本名。CLI、退出码、
  规则库、tag 序列全部不变，`v1.0.0`~`v2.2.1` 是同一条提交线。遇到旧名引用不要当成另一个技能。

### 0.2 退出码契约 — 判定以此为准

| verdict | exit | 含义 | 你该做什么 |
|---------|------|------|-----------|
| `PASS` | 0 | 无问题 | 可发布 |
| `NEEDS_FIX` | 2 | 仅建议项（medium/low） | 修完再发，或明确告知用户「不阻断但建议处理」 |
| `BLOCKED` | 1 | 命中 blocker | **必须修**，否则被平台拒或下架 |

- `--format json` 时 stdout 只有 JSON，错误信息走 stderr，可直接 pipe。
- 退出码是给 CI 用的；**给用户的结论以 verdict 字段为准**，别只看 exit。

### 0.3 执行模型

- 默认只扫 git 跟踪集（等价「发布所见」）。目标不是 git 仓库时自动全扫；
  要强制全扫加 `--all-files`。
- 默认零出网、零必需密钥。**只有 `--deep-scan` 会执行外部命令**——用户没显式给出
  该命令就不要用；用了就必须在报告里说明「深度结果来自外部扫描器」。
- 性能：600 文件约 3 秒。若明显更久，先看是不是目录里混了大产物。

### 0.4 三条铁律（都是踩过的坑）

1. **「功能合法」≠「文档合规」**：功能完全合法，但一句「提升海外源可达性」就会被判违规。
   修文档措辞，不要试图解释功能。
2. **`--proxy` 的正确写法**：定位为「企业内网要求出站流量经统一代理」的通用 HTTP 参数，
   明写「仅用于合法的企业内网出站场景，不提供也不支持任何规避网络管理措施的能力」。
3. **降级而非绕行**：外部源不可达时既定行为是降级到国内源 + 离线快照 + 如实标注，
   而不是「配代理恢复访问」。

---

## §1. 单次执行流程 — 5 步，单轮内闭环

每步都写明了输入 / 输出 / 失败兜底。**不要跨轮次重新读本文件**，五步走完即完成。

### Step 1 — 确认目标与口径

- **输入**：用户指的 skill 目录（未指明则问，或用 `dirs` 列候选）；目标平台。
- **动作**：确定 `--dir` 与 `--platform`（默认 `skillhub`）。平台不确定就问用户——
  口径错了结论没意义。`github` 用于开源副本，`clawhub` / `ima` 有各自放宽或加严的口径。
- **输出**：一条确定的命令，形如
  `python scripts/gate.py check --dir <目录> --platform <平台>`。
- **失败兜底**：`--dir` 不存在或不是目录 → exit 2 报错（v2.2.1 起不会静默审别的东西）。
  目标目录缺 `SKILL.md` → 报 `FM-001` / BLOCKED，这是正确行为不是 bug。

### Step 2 — 跑门禁

- **输入**：Step 1 的命令。需要机器可读就加 `--format json`；批量用 `dirs`。
- **动作**：执行。要看默认静音的 INFO 级命中（出站代理等）加 `--show-info`。
- **输出**：verdict + exit code；`--format json` 时还有 `issues[]`（每条含
  `rule_id` / `severity` / `file` / `line` / `found` / `recommendation`）。
- **失败兜底**：脚本缺 PyYAML 会自动尝试安装；装不上则作为 BLOCKER 报错退出，
  **绝不静默通过**。若加过 `--deep-scan` 而扫描器失败，本地判定照常出结论，
  只少一层深度结果——在报告里如实说明。

### Step 3 — 定位并解释命中

- **输入**：Step 2 的 issues。
- **动作**：按 `file:line` 打开真实代码/文档核对。**不要照抄 `recommendation` 就动手**——
  先确认它在当前上下文里是否仍成立（尤其是 L0 与 L2 报同一位置时，以 L0 为准）。
  命中属于哪一类不确定时，查 `references/rule-catalog.md`。
- **输出**：每条命中一句话说明「是什么问题 + 为什么这次是真问题」。
- **失败兜底**：判不准的标为「疑似、需人工确认」，不要下断言。
  INFO 级默认不计入 verdict，但仍值得在报告里提一句。

### Step 4 — 修或给建议

- **输入**：确认为真的命中。
- **动作**：能直接改的就改（措辞类问题优先改文档而不是改功能）。改完**重新跑一次 Step 2**
  验证——本门禁自身 dogfood，改完不复跑等于没验证。
- **输出**：修改清单 + 复跑后的新 verdict。
- **失败兜底**：某条改不动或不该改（是误报），告诉用户**为什么不改**，并给出可选的
  `--learn '{"type":"whitelist",...}'` 回灌建议——但**必须由用户确认后才执行**，
  白名单对所有规则生效，包括红线。

### Step 5 — 交付结论

- **输入**：最终 verdict + 修复情况。
- **动作**：给出「结论 + 阻断项 + 建议项」三段式，并附上 0.2 的免责声明
  （本地预检，非平台审核保证）。若用了外部扫描器结果，注明来源。
- **输出**：用户可以直接据此决定「发」或「先修」。
- **失败兜底**：判 BLOCKED 而用户想直接发 → 明确说清会被平台拒/下架的具体条款，
  不要软化。判 PASS 也要提醒「平台审核独立进行」。

---

## §2. 触发示例

**会触发**：

> 「我要把这个 skill 发到 SkillHub 了，先帮我跑一遍门禁看看有没有会被拒的问题」

→ 识别为 Step 1，平台明确是 skillhub，直接 `check --platform skillhub`。

**不会触发**：

> 「帮我扫一下这个仓库有没有 SQL 注入和 XSS 漏洞」

→ 不触发。这是**深度应用漏洞审计**，本门禁刻意不做（它要的是「发布前 5 秒看出会不会被拒」，
不是把代码审穿）。应改用 CodeQL / Semgrep / domsec / Codex Security；
若用户已有它们的 SARIF 报告，可用 `--sarif-in` 把结果并进本门禁的同一个 verdict。

**同样不触发**：

> 「帮我看看这段 Python 为什么报错」→ 是代码调试，不是发布预检。

---

## §3. 边界与分工

| 需求 | 归谁 |
|------|------|
| 发布包门禁（包内容 + 结构 + 措辞 + 轻量安全） | **本门禁** |
| 深度源码漏洞（AST / 污点 / CVE） | CodeQL / Semgrep / domsec / Codex Security |
| 专用密钥扫描 | gitleaks（本门禁只做包内凭据形态粗检，CI 里可叠加） |
| 国内监管合规文书（金融/广告法/隐私法律依据） | skill-compliance-check |
| 已上架 skill 的线上行为监控 | 平台侧 / 运行时方案 |

**不适用场景**（别硬套）：非 skill 目录的通用扫描；把门禁结论当审核保证；
对已发布 skill 做回归监控。

## §4. 本技能自己的发布形态

1. `check --dir .`（默认 skillhub）预期 **BLOCKED**（本仓库含 `.gitignore`/`.github`，
   属 SkillHub 发布需排除项）；`--platform github` 预期 **PASS**；
   `--platform clawhub` 预期 **NEEDS_FIX**（frontmatter 含 `license: MIT-0` 与
   `subprocess` 未声明 `requires`，各触发一条 WARN，均属预期）。
2. 发布前用 `git archive HEAD` 导出干净副本，**别 `publish .` 仓库目录**。
3. 不写 `license:` 字段（避免踩 ClawHub 强制 MIT-0 的明文禁令，跨平台各出副本）。

## §5. 改名对照（只需知道结论：同一个东西）

| 旧 | 新 |
|---|---|
| `@skill:skillhub-gate` | `@skill:skill-publish-gate` |
| `skillhub install skillhub-gate` | `skillhub install skill-publish-gate` |
| `python gate.py check ...` | 完全不变 |
| `ai-weekly-publish-gate` | v2.0.0 起并入本门禁，老目录仅剩重定向说明 |

改名理由：老名字把「SkillHub」这一种平台写进了技能身份，而本门禁同时守多个平台，
还带代码安全一层——旧名会把能力边界讲窄。

## §6. 免责声明

本门禁仅做本地规范预检与静态安全扫描，**不构成任何平台的上架保证**。SkillHub 为三线并行审核
（内容合规过滤 + 深度漏洞扫描 + 模型安全评估），ClawHub 为「安全扫描 + 强制 MIT-0 +
声明一致性」，ima 有独立的七字段与文件命名口径。这些判定由平台侧做出。最终能否上架由平台
审核决定，责任由开发者自行承担。
