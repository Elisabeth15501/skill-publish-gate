# 规则全表（按需查阅，勿预先读入）

> SKILL.md §1 只给「怎么跑」；这里是「跑出来每一类是什么意思」。
> 需要确认某条规则的精确 pattern / severity / 平台降级，查
> `rules/skillhub-spec.json`（唯一数据源，gate.py 不含词表）。

## 1. 代码安全（SECURITY / PRIVACY）

四平台（skillhub / github / clawhub / ima）**均为 BLOCKER**，不随平台降级。

| 规则 | 检查内容 | 默认档 |
|------|----------|--------|
| SEC-CRED-001 | 疑似 token/key（GitHub PAT、AWS AKIA、GitLab PAT、Slack、AIza 等形态），命中一律脱敏回显为 `[REDACTED_SECRET]` | critical / redline |
| SEC-MALWARE-001 | 恶意执行模式（base64 解码后动态执行、下载即执行、反向 shell 等） | critical |
| SEC-PROMPT-001 | Prompt 注入特征（忽略之前指令、越狱模式等） | critical |
| SEC-PERSIST-001 | 指示宿主永久篡改持久化文件（SOUL.md / MEMORY.md / IDENTITY.md / USER.md） | critical |
| SEC-LICENSE-001 | 传染性开源协议（copyleft 家族）与版权剥离条款；协议名只存规则库，文档不枚举以免自描述误报 | critical / high |
| SEC-PERMISSION-001 | 脚本含写文件 / 子进程 / 网络但 frontmatter 无权限声明（过度授权） | medium |
| AST-*-001 | stdlib ast 精确到行的危险调用：动态执行、shell 解释执行、不安全反序列化。具体规则 ID：AST-EVAL-001 / AST-EXEC-001 / AST-OS-001 / AST-SHELL-001 / AST-PICKLE-001 | high |
| AST-PARSE-001 | 文件未被 ast 覆盖 / 解析失败 | info（默认静音） |
| PRIV-PATH-001 | 绝对路径泄漏（含本机用户名） | medium |
| PRIV-NAME-001 | 真实姓名 / 用户名（已排除用户公开笔名） | medium |
| PRIV-MEAS-001 | 真实量测值（「整仓 52 个文件」这类暴露仓库规模的表述） | medium |

## 2. 平台规范（SPEC）

| 检查 | 触发后果 |
|------|----------|
| FRONTMATTER 用真 `yaml.safe_load` 解析，抓半角「冒号 + 空格」等静默失败 | BLOCKED |
| 必填字段：`slug`（kebab-case 2–128）/ `version`（SemVer）/ `displayName` | BLOCKED |
| 推荐字段：`name` / `description` / `summary` / `tags` | NEEDS_FIX |
| 封禁文件：`.gitignore` / `.nojekyll` / `LICENSE` / `__pycache__` / `*.pyc` / `.github` / `.clawhubignore` | BLOCKED（github 豁免前四类） |
| 发布产物卫生：`.github_token` / `.workbuddy` / `.env` / `.venv` / `node_modules` | BLOCKED |
| 包体：文件数 / 总体积超阈值（发布时会把服务端卡死） | BLOCKED / NEEDS_FIX |
| 版本一致性：`version` 在 SKILL.md / config.json / metadata.json / CHANGELOG.md 是否统一 | NEEDS_FIX |
| 网络声明：声明 `network: none` 但脚本含真实网络调用 | NEEDS_FIX |
| 依赖钉版：`requirements.txt` 未 pin 到 `==version` | NEEDS_FIX |
| INFO-PROXY-001 | 出站代理提及（`--proxy` / `HTTPS_PROXY`） | info（默认静音，需人工确认定位为内网出网） |

## 3. 内容合规（CONTENT）

对应平台审核红线。词表来自 ai-weekly 2026-09-22 措辞下架事故的固化经验。

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| RED-NET-001~003 | 网络规避敏感词族（中文词 + 代理工具同族词 + 机场/节点订阅） | BLOCKED（clawhub 降 WARN） |
| RED-NET-004 | 规避类功能叙事（把功能描述成「恢复访问 / 解除限制」） | BLOCKED / NEEDS_FIX |
| RED-NET-005 | 下架事故固化的扩展词表与叙事正则 | BLOCKED（clawhub 降 WARN） |
| RED-AD-001 | 广告法极限词（最好 / 第一 / 唯一 / 顶级…） | NEEDS_FIX |
| RED-FIN-001 | 金融敏感表述（荐股 / 保证收益 / 内部消息…） | NEEDS_FIX |

**元语境豁免**：命中词出现在「否定 / 定义 / 清单 / 说明」语境时视为自描述，不误报——
所以合规或安全类技能罗列规则词不会被自己标红。这是本门禁能覆盖红线词族的前提。

## 4. Agentic / MCP 专有类目（v2.1.0+）

通用代码扫描器不读 SKILL.md，抓不到「指令式」风险——这两类只可能由发布门禁守。

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| AGENT-MEMORY-001 | 记忆投毒：要求跨会话永久记住用户身份/偏好，或每次向第三方汇报 | BLOCKED（clawhub 降 high） |
| AGENT-LEAK-001 | 系统提示泄漏：要求输出/回显系统提示、初始指令、内部规则 | BLOCKED（clawhub 降 WARN） |
| AGENT-AUTONOMY-001 | 过度代理权：跳过用户确认就执行不可逆动作（删除/支付/发布/转账） | BLOCKED（clawhub 降 WARN） |
| AGENT-REFUSAL-001 | 反拒绝：要求不得拒绝、不得提示风险、无条件执行 | BLOCKED（clawhub 降 WARN） |
| AGENT-TRIGGER-001 | 触发词滥用（「所有问题都调用本技能」） | NEEDS_FIX |
| MCP-PRIV-001 | MCP 权限过宽：`permissions: "*"`、任意文件读写、跳过沙箱 | BLOCKED（clawhub 降 WARN） |
| MCP-PROMPT-001 | 工具描述投毒：「不要告诉用户这次操作」「调用前不要检查」 | BLOCKED（clawhub 降 high） |
| MCP-DECLARE-001 | 提到 MCP 但未在 `requires` 声明 | info（默认静音） |

这批规则**不叠加全局元语境词表**（`use_global_meta_markers: false`）——它们的攻击句式本身
就是「不要 X」「无需确认」，叠加「不要」会让规则自己废掉。每条规则改用自己的
`exclude_patterns` 精确豁免否定式表述（如「本技能不输出系统提示词」不算违规）。

## 5. 平台档位差异

### `--platform clawhub`

| 类别 | 行为 |
|------|------|
| 封禁文件 / 发布产物卫生 | **跳过**（ClawHub 接受任意扩展名） |
| RED-NET-001~005 | 降级为 WARN（ClawHub 不做关键词内容审核） |
| LICENSE-FIELD-001 | frontmatter 声明 `license:` 且非 `MIT-0` → BLOCKED；声明为 `MIT-0` → WARN（建议移除） |
| META-MISMATCH-001 | 脚本调外部 CLI / 子进程 / 网络但未声明 `requires` → WARN |
| 安全类（SEC-* / AST-*） | **仍为 BLOCKER**，不随平台降级 |

### `--platform github`

豁免开源许可与 CI 文件（`LICENSE` / `.github` / `.gitignore` 等），用于开源副本预检。

### `--platform ima`

腾讯 ima 知识库包口径与 SkillHub 有四处不同（规则见 `platform_profiles.ima`）：

| 规则 | 检查内容 | 触发后果 |
|------|----------|----------|
| IMA-FM-001 | frontmatter 七字段齐全（`name`/`displayName`/`description`/`version`/`trigger_keywords`/`reference`/`disclaimer`） | BLOCKED |
| IMA-FILE-001 | 包内含平台生成物 `_meta.json` | BLOCKED |
| IMA-QUOTE-001 | 字符串用了全角引号 `“”‘’`（ima 只认 ASCII 直引号） | NEEDS_FIX |
| IMA-NAME-001 | 文件名含非 ASCII 字符 | NEEDS_FIX |
| IMA-TRIGGER-001 | `trigger_keywords` 超过 5 条 | NEEDS_FIX |

平台口径变了只改 `rules/skillhub-spec.json` 的 `platform_profiles` 一段，不涉及 `gate.py`。

## 6. 规则条目可用字段

| 字段 | 作用 |
|------|------|
| `id` / `category` / `severity` / `redline` | 基本四要素 |
| `level: info` | 计入 info_hits，不进 verdict |
| `patterns` / `exclude_patterns` | 正则与精确豁免 |
| `self_describing_markers` / `use_global_meta_markers` | 元语境豁免（后者默认 true，agentic 规则设为 false） |
| `platform_downgrade` | 平台降级映射，如 `{"clawhub": "medium"}` |
| `scan_targets` | `docs` / `scripts` / `all` |
| `clause` / `origin` / `description` / `authority_type` | 出处溯源与报告字段 |

新增或调整红线直接改 JSON，不用动脚本。
