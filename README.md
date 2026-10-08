# skill-publish-gate · Skill 发布门禁（代码安全 + 平台规范）

[![license: MIT-0](https://img.shields.io/badge/license-MIT--0-blue.svg)](LICENSE)

一个 skill 要发出去之前，本来要跑两个工具：**代码安全**（凭据 / 注入 / PII / 恶意模式）
和**平台规范**（frontmatter 硬校验 / 封禁文件 / 包体 / 声明一致性）。
本门禁把两件事收成一条本地命令，并带上国内平台的内容措辞红线。

> **更名**：本技能原名 `skillhub-gate`（v1.0.0 ~ v1.4.0 的历史完整保留），2026-10 更名为
> `skill-publish-gate`。代码、CLI、退出码、规则库均不变，只是不再把某一家平台写进技能身份。
> 旧名 `@skill:skillhub-gate` / `skillhub install skillhub-gate` 请按新名调用。

> **v2.1.0 起新增缝接层**：SARIF 2.1.0 双向（`--format sarif` / `--sarif-in`）、统一指纹与基线
> （`--baseline`）、外部配置（`--config` / `--strict`）、外部扫描器调用（`--deep-scan` /
> `--offline`）、stdlib ast 危险调用精确行号、agentic 与 MCP 专有类目、`--platform ima`。

> v2.0.0 起合并了 **ai-weekly-publish-gate**（国内平台措辞红线 + `--learn` 回灌闭环），
> 词表与叙事正则全部落到 `rules/skillhub-spec.json`，不再依赖任何外部仓库。
> 结构化对标 [skill-compliance-check](https://github.com/)（脚本 + 规则 JSON + 子命令）。

## 为什么需要它

- `skillhub publish --dry-run` 只校验 frontmatter，**封禁文件类型要等正式发布才报 400**；
- 仓库混入测试产物（`allure-results` / `.pytest_cache` / `data` / `.venv` / `node_modules`）
  会让发布包上万 part，服务端处理时卡死无输出；
- 内容审核三线并行，文档里的网络规避词族、绝对化用语、金融敏感表述会拒或下架；
- 安全侧（凭据 / Prompt 注入 / 恶意执行模式 / PII）发布前通常没人查，等平台安全扫描打回时已下架。

门禁把这些「服务端才暴露」的失败，提前到本地一条命令看出来。

## 安装

```bash
# 方式 A：克隆到 WorkBuddy 技能目录
cd ~/.workbuddy/skills
git clone https://github.com/<你>/skillhub-gate.git

# 方式 B：对话里一句话装（已连 GitHub 连接器时）
# 帮我安装这个 skill：https://github.com/<你>/skill-publish-gate

# 方式 C：从 GitHub 导入 ClawHub（clawhub.ai → import → 填仓库地址）
```

依赖：PyYAML。脚本缺失时自动尝试 `pip install pyyaml`；仍不可用则作为 BLOCKED 报错，
**不会在无法 faithful 解析时放行**。

## 文档分层（v3.0.0 起）

`SKILL.md` 只放**每轮都要用**的东西：`§0 硬约束`（每轮必读，上下文压缩后也要重新遵守）
与 `§1 单次执行流程`（5 步，单轮闭环）。其余按需读：

| 文件 | 内容 | 什么时候读 |
|---|---|---|
| `SKILL.md` | 硬约束 + 5 步流程 + 触发示例 | 每次触发都读 |
| `references/rule-catalog.md` | 规则全表、平台档位差异、规则字段说明 | 不确定某条规则查什么/什么档位 |
| `references/cli-reference.md` | CLI 参数全表、缝接层、基线、config、JSON schema | 需要组合参数或读 JSON 字段 |

这样切分是为了让每次触发只读必要内容：v2.x 的 `SKILL.md` 把规则全表和参数表都塞在正文里，
每次触发都要付这份 token，而真正需要反复遵守的硬约束反而容易被上下文压缩挤掉。

## 快速开始

```bash
# 单技能门禁（默认 skillhub 平台：LICENSE 等是封禁 blocker）
python scripts/gate.py check --dir <skill目录>

# 开源副本预检（github 平台：LICENSE 等许可文件豁免，仍查其余红线）
python scripts/gate.py check --dir <skill目录> --platform github

# ClawHub 预检（接受任意扩展名；措辞词族降级为 WARN；补 MIT-0/requires 一致性检查）
python scripts/gate.py check --dir <skill目录> --platform clawhub

# ima 预检（七字段 / 零 _meta.json / ASCII 引号 / 纯 ASCII 文件名 / 触发词 ≤5）
python scripts/gate.py check --dir <skill目录> --platform ima

# 产出 SARIF 2.1.0（喂 GitHub Code Scanning）
python scripts/gate.py check --dir <skill目录> --format sarif -o gate.sarif

# 导入外部深度扫描器的 SARIF（finding 封顶 medium 后并入判定，不阻断）
python scripts/gate.py check --dir <skill目录> --sarif-in domsec.sarif

# 直接调外部扫描器（不经 shell；失败不影响本地判定；{dir} = 目标目录）
python scripts/gate.py check --dir <skill目录> \
    --deep-scan "python3 ~/tools/scanner.py --format sarif {dir}"

# 基线：抑制「确认过的误报」（指纹跨运行稳定，被抑制项降为 info 仍可追溯）
python scripts/gate.py check --dir <skill目录> --write-baseline ./baseline.json
python scripts/gate.py check --dir <skill目录> --baseline ./baseline.json

# 外部配置：阈值 / 封禁文件追加 / 自定义规则（只许更严，--strict 可锁死）
python scripts/gate.py check --dir <skill目录> --config ./gate.json

# 机器可读 / 落盘
python scripts/gate.py check --dir <skill目录> --format json
python scripts/gate.py check --dir <skill目录> --output gate-report.txt

# 批量汇总（父目录下所有含 SKILL.md 的技能）
python scripts/gate.py dirs --dir ~/.workbuddy/skills

# 回灌：平台审核发现的新坑写回 rules/feedback.json
python scripts/gate.py check --dir <skill目录> --learn '{"type":"blocker","pattern":"新危险词","reason":"平台审核打回：..."}'
```

退出码：`0`=PASS，`2`=NEEDS_FIX，`1`=BLOCKED。可直接接 CI / pre-publish hook。

## 检查项一览

### 代码安全（`SECURITY` / `PRIVACY`，跨三平台均为 BLOCKER）

| 类别 | 内容 | 后果 |
|------|------|------|
| 凭据泄漏 | 疑似 token/key（ghp_/sk-/AKIA/glpat-/xoxb-/AIza 等），命中脱敏回显 `[REDACTED_SECRET]` | BLOCKED |
| 恶意执行 | base64 解码后 eval/exec、下载即执行、反向 shell、`rm -rf /` 等 | BLOCKED |
| Prompt 注入 | 忽略之前指令 / 越狱 / DAN 等特征 | BLOCKED |
| 持久化篡改 | 指示宿主永久改写 SOUL.md / MEMORY.md / IDENTITY.md / USER.md | BLOCKED |
| 传染性协议 | copyleft 家族协议与版权剥离条款 | BLOCKED / NEEDS_FIX |
| 隐私 / 权限 | 绝对路径泄漏、真实姓名、真实量测值、权限声明缺失 | NEEDS_FIX |

### 平台规范（`SPEC`，随平台口径变化）

| 类别 | 内容 | 后果 |
|------|------|------|
| FRONTMATTER | 真 YAML 解析 / `slug`+`version`+`displayName` 必填 / SemVer | BLOCKED |
| 封禁文件 | `.gitignore`/`.nojekyll`/`__pycache__`/`*.pyc`/`.clawhubignore`/`.pytest_cache` 等；`LICENSE` 等仅在 `--platform skillhub` 拦，`--platform github` 豁免 | BLOCKED |
| 发布产物卫生 | `.github_token` / `.workbuddy` / `.env` / `.venv` / `node_modules` 不得进包 | BLOCKED |
| 包体 | 文件数 / 体积超阈值 | BLOCKED / NEEDS_FIX |
| 版本一致性 | 多处 `version` 是否统一 | NEEDS_FIX |
| 网络声明 | `network:none` 与脚本实际调用是否一致 | NEEDS_FIX |
| 依赖钉版 | `requirements.txt` 未 pin 到 `==version` | NEEDS_FIX |
| INFO 级 | 出站代理提及，默认静音，`--show-info` 才显示 | 不阻断 |

### 内容措辞（`CONTENT`，对应平台审核红线）

| 类别 | 内容 | 后果 |
|------|------|------|
| 网络规避词族 | `RED-NET-001~005`（中文词 + 代理工具同族词 + 机场/订阅 + 下架事故固化的扩展词表与叙事正则） | BLOCKED（clawhub 降级 WARN） |
| 绝对化用语 | 广告法极限词（最好/第一/唯一/顶级…） | NEEDS_FIX |
| 金融敏感表述 | 荐股 / 保证收益 / 内部消息… | NEEDS_FIX |
| 出站代理提及 | INFO 级，需人工确认定位为企业内网出网 | 不阻断 |

> 元语境豁免：命中词出现在「否定 / 定义 / 清单 / 说明」语境（如「检测网络规避敏感词」）时
> 视为自描述，不误报——合规与安全类技能罗列规则词不会被自己标红。

规则集中在 `rules/skillhub-spec.json`，调整红线改 JSON 即可（规则引擎直接把 `patterns`
当正则编译，元语境豁免 / 平台降级 / 白名单 / 回灌都在脚本侧统一处理）。

## 回灌闭环（防复发）

平台审核若暴露新坑，用 `--learn` 写回 `rules/feedback.json`：

```bash
# 新危险词 → 追加为额外 BLOCKER
python scripts/gate.py check --dir <skill目录> --learn '{"type":"blocker","pattern":"新危险词","reason":"平台审核打回：..."}'
# 已知误报 → 加入白名单（命中静音，不哑掉真问题）
python scripts/gate.py check --dir <skill目录> --learn '{"type":"whitelist","pattern":"企业内网出站","reason":"已确认定位为内网场景"}'
# 弱建议 → 追加为额外 WARN
python scripts/gate.py check --dir <skill目录> --learn '{"type":"warn","pattern":"某弱建议表述","reason":"..."}'
```

`learned_blockers`/`learned_warns` 下次扫描即作为增量规则，`whitelist` 命中即静音。
私有白名单只静音确认过的误报，不污染默认规则库。

## 与其他工具的分工

| 工具 | 主场 | 与本门禁 |
|---|---|---|
| skill-publish-gate（本） | 发布包门禁：包内容 + 结构 + 措辞 + 轻量安全 | — |
| skill-compliance-check | 国内监管合规（金融 / 广告法 / 隐私法律依据） | 本门禁管「能不能发」，它管「发上去合不合规」 |
| CodeQL / Semgrep / domsec | 工业级源码漏洞分析（AST / 污点 / CVE） | 本门禁是发布前快检，深层审计走它们 |
| gitleaks | 专用密钥扫描 | 本门禁只做包内凭据形态粗检，CI 里可再叠一个 |
| 平台安全扫描 | VirusTotal / LLM 评估 / 模型安全 | 本门禁是它们的本地预演 |

## 缝接层：谁做深度分析可以换，谁来判能不能发不换

本门禁只判「这个 skill 能不能发布」，不重复造通用代码审计。深度那层通过三个入口接进来：

| 入口 | 做什么 | 什么时候用 |
|---|---|---|
| `--format sarif` | 产出 SARIF 2.1.0 | 接 GitHub Code Scanning，或喂给别的工具 |
| `--sarif-in FILE` | 吃任意外部 SARIF | 已有 domsec / SkillSpector / Codex Security 的报告 |
| `--deep-scan CMD` | 直接调外部扫描器 | 想在一次门禁里串起深度扫描 |

两条不变量：

1. **外部 finding 档位封顶 medium**（error→medium、warning→low），且不带 redline —— 所以深度层
   永远不能单独决定能不能发。依据是 LLM 语义层实测精度约
   87%——把它的 critical 直接当 BLOCKER 会被误报轰炸，用户随后只会把工具关掉。
   已过验证层的工具可加 `--sarif-trusted` 恢复原始档位。
2. **深度层失败绝不影响本地判定**。扫描器挂掉、超时、输出不合法，都只记一条日志。

`--offline` 是硬开关：与 `--deep-scan` 互斥。理由是 Codex Security 必须登录、domsec 要把源码
传给第三方——而这个门禁的存在理由之一就是「一个字节都不外传」，那就该做成开关而不是文档承诺。

## 四条铁律（写进技能文档时牢记）

1. **功能合法 ≠ 文档合规**：文档绝不出现法律含义明确的敏感词，更不把功能描述成「解决某类访问限制」。
2. **`--proxy` 定位为企业内网统一出网**，明写「不提供也不支持任何规避网络管理措施的能力」。
3. **降级而非绕行**：海外源不可达就降级到国内源 + 离线快照 + 如实标注。
4. **默认零出网**：不带 `--deep-scan` 时不发起任何网络请求、不读任何环境变量、不需要任何密钥。

## 跑测试

```bash
python tests/run_all.py          # 全部（约 80 秒）
python tests/test_modules.py     # 单元测试
python tests/test_p0_verify.py   # 对抗式审查里那三个攻击的原样重打
```

测试全部用相对路径定位，可在任意机器 clone 后直接跑，无外部依赖（PyYAML 除外）。
`test_p0_verify.py` 是对抗式审查的回归防线——**它把当初真实打中过的攻击原样重放**，
不是重写等价用例；改动 `--config` / `--baseline` / `--platform` / SARIF 相关逻辑前，
请先跑它。

## 贡献

PR 欢迎。技能是给 Agent 的任务说明书，改动建议聚焦一处痛点、附带真实触发样例与预期输出。
规则调整优先改 `rules/skillhub-spec.json`（数据外置），脚本逻辑改动请同步更新 `CHANGELOG.md`。

## 许可证

[MIT-0](LICENSE) — 无需署名，可自由使用、修改、再分发。

## 免责声明

本门禁仅做本地规范预检与静态安全扫描，**不构成任何平台的上架保证**。SkillHub 为三线并行审核
（内容合规过滤 + 深度漏洞扫描 + 模型安全评估），ClawHub 为「安全扫描 + 强制 MIT-0 + 声明一致性」。
最终能否发布由平台审核决定，责任由开发者自行承担。
