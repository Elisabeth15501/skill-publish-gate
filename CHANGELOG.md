## [2.2.1] — 2026-10-08

**这一版处理对抗式审查里的「一般」级 5 项**：P1-4 指纹 / P1-5 原子写 / P1-6 `--dir` 校验 /
P1-7 跨工具去重 / P1-8 测试入库；外加 M2 已被 v2.1.1 的缓存顺带解决。
判据归属与退出码均未变 → **PATCH**。

### P1-4 · 指纹不再含行号，基线抗代码漂移（一般）

**问题**：指纹键含 `line`，在文件开头加一行注释，后面所有 finding 的行号平移，
**整份基线当场失效**——而基线的意义恰恰是「记住我确认过这些是误报」。

**修法**：指纹改 `sha256(原始rule_id | file | occurrence | title)`，去掉行号。
但**不能简单去掉**——同一文件同一规则可能命中多处（requirements.txt 三行都没钉版），
去掉行号会把它们折叠成一条，「报 3 条」变成「报 1 条」，那是漏报。
所以引入 `occurrence`（同一 文件+规则 下的第几次命中）替代行号：它的稳定性远好于行号
（改别的行不影响它，只有增删同规则命中才变）。基线文件 `schema: 2`，旧版读入时
失配并**明确提示重建**，不静默失效。

### P1-5 · `save_feedback` 改原子写（一般）

**问题**：`open(path, "w")` 直接截断重写，两个风险——并发回灌互相覆盖；
另一个进程在写入中途 `json.load` 会失败，而 `load_feedback` 对失败返回空结构，
于是**回灌记录凭空消失且无任何提示**。

**修法**：写同目录临时文件 + `os.replace` 原子替换（replace 在同一文件系统内是原子操作，
读者要么看到旧内容要么看到新内容）。临时文件必须与目标同目录，跨文件系统会失败。
实测并发 8 次写入：文件始终是合法 JSON、无 `.tmp` 残留。
（注：last-writer-wins 导致的条目丢失是固有的，原子写解决的是「读到半截」与「覆盖写」；
彻底解决需要文件锁，不在本次范围。）

### P1-6 · `--dir` 非目录直接报错（一般）

**问题**：`--dir /nonexistent/path` 会被接到 cwd 后面变成
`C:\Program Files\...\nonexistent\path`，skill 名取 basename 成了 `path`——
**用户以为门禁审了一个叫 path 的 skill，还拿到了一个看似正常的 JSON 报告**。
拼错路径后静默审别的东西，比报错坏得多。

**修法**：`os.path.isdir` 校验，失败 exit 2 并回显解析后的绝对路径 + 区分「不存在」与「不是目录」。

### P1-7 · 跨工具去重真正生效（一般 / 建议 G4）

**问题**：L2 的 rule_id 被加 `L2-` 前缀，指纹用带前缀的值 → L0 与 L2 报同一件事
**永远折叠不掉**，「跨工具去重」是一句空话。

**修法**：拆成两个键，各司其职——
- `issue_identity` = `file + 原始rule_id`（剥掉来源前缀）：用于**精确去重**，
  dedupe 的判据是「身份键 + 行号」，所以跨工具同一位置会折叠、同文件多行仍全保留
- `issue_fingerprint` = 原始 rule_id + file + occurrence + title：用于**基线**，不含行号以抗漂移

`occurrence` 的分组键用**剥离前缀后**的 rule_id，否则 L0 与 L2 会分到不同组各取 0，
后面剥了前缀也拼不回原指纹。

### P1-8 · 测试入库（一般 / 审查 M5）

**问题**：5 个测试脚本、140+ 项断言全在工作区，**仓库里一个都没有**。
clone 下来的人没有任何回归保护——本 skill 自己就是门禁工具，却没给自己留门禁。

**修法**：`tests/` 目录入库（`test_modules` / `test_e2e` / `test_p0_verify` /
`test_p17_verify` / `test_m3_verify`），路径全部改为相对定位
（`os.path.normpath(os.path.join(HERE, "..", "scripts"))`），
不再硬编码 `C:/Users/elisa/...`——顺带解决了「测试里含真实用户名路径」这个隐私问题。

另加 `tests/run_all.py` 聚合入口：一个命令跑完全部，失败返回 exit 1。
理由：门禁是「发布前最后一道闸」，如果回归测试只能靠记住五个文件名逐个跑，
三个月后就没人跑了。实测全量 79 秒。

### 验证

- 新增 `_test_p17_verify.py`（10 项）：跨工具折叠生效 + 三种反向场景不误折叠 + 行号漂移后基线仍命中
- 新增 `_test_m3_verify.py`（8 项）：原子写与并发
- 模块单测 baseline 段重写（旧断言写死了 `load_baseline` 返回 set，现改为 tuple），
  补 schema / 旧版提示 / 抗漂移 / 防漏报四组断言
- `tests/run_all.py` 五套全绿；四平台零回归；tests/ 目录入库后自审结果不变

### 过程中两次「测试伪装成缺陷」

- 模块单测里 `suppressed[0]` 假设了顺序——`assign_occurrences` 按 `(file, rule_id, line)` 排序分配
  occurrence，写入顺序与原列表不一定一致。断言改为集合比较
- 「dedupe 折叠重复项」原本期望 3 条输入得 2 条；改用「身份键 + 行号」判据后，
  完全重复的条目（含 line）确实折叠，行为正确，是断言的期望值需要跟着更新

**教训（同 v2.2.0）：断言必须对齐「意图」而非「当前实现」。**

### 计划文档已同步

`代码质量优化计划.md` 加了进度看板：P0 四项 ✅ v2.1.1、P1-1/2/3 ✅、
P1-4/5/6/7 ✅ v2.2.1、P1-8（测试入库）⬜ 未做。
并写明版本号判定依据：**改 exit code 或 verdict 归属 → MINOR；只让 bug 不再发生 → PATCH**。

---

## [2.2.0] — 2026-10-08

**这一版关掉对抗式审查里剩下的两个严重项（S2 / S6）。**
3 个阻断与 4 个严重（S1 性能 / S3 `--strict` / S4 `level=info` / S5 ReDoS）已在 v2.1.1 关闭。

### S2 · L2 finding 档位封顶 medium，深度层不再有阻断权（严重）

**漏洞**：SKILL.md / README / CHANGELOG 三处都写「外部 finding 一律降一级且不阻断」，
但 `_L2_DOWNGRADE` 是 `critical → high`，而 `high` 仍在 `BLOCKER_SEVERITIES` 里。
实测 `level=error` 的外部 finding 照样 `BLOCKED exit 1`——**文档承诺了一件假的事**。

**修法**：降级表改为**封顶 medium**（error→medium、warning→low、note→low），
`--sarif-trusted` 是唯一例外（调用方声明该工具的 finding 已过验证层时恢复原档）。

设计意图写进了代码注释：**深度层只能提供线索，不能单独决定发布与否**。
LLM 语义层实测精度约 87%，把它的判断直接当 BLOCKER 会被误报轰炸，
用户随后只会把工具关掉——那才是更糟的结局。medium 是 NEEDS_FIX：
出现在报告里、让 verdict 变黄，但不阻断。

四档实测：`error → medium` / `warning → low` / `note → low`，verdict 均为 `NEEDS_FIX exit 2`；
`--sarif-trusted` 才回到 `critical` / `BLOCKED exit 1`。

### S6 · `--platform` 恢复白名单校验（严重）

**漏洞**：v2.1.0 为支持从 `--config` 读 platform，把 argparse 的 `choices` 一起去掉却没补回校验。
后果是 `--platform clahub` 静默按 skillhub 跑完并正常出报告——
**用户以为按 ClawHub 口径审过了，实际没有**。这类「拼错照跑」的失败比报错更坏。

**修法**：新增 `PLATFORMS` + `resolve_platform()`，在**解析之后、构造 gate 之前**校验：

- 优先级：命令行 > `--config` 的 platform > 默认 `skillhub`
- 非法值 exit 2，报错列出四个合法取值，并提示「ClawHub 是 `clawhub` 不带大写」
- `dirs` 子命令走同一套校验（批量体检最忌「拼错平台、整批按错口径跑完还照样出表」）
- 报错走 **stderr**，保持 stdout 只有报告本体（`--format json` 可直接 pipe）

### 验证

- `_test_p0_verify.py` 扩展 13 条断言（3 原始攻击 + S2 六条 + S6 四条）
- 模块单测 + 端到端补 L2 封顶与 trusted 例外断言
- 三套共 124 项全绿；四平台零回归（BLOCKED(2) / PASS / NEEDS_FIX(2) / ima BLOCKED）
- 性能未受影响（600 文件 2.9s）

### 顺带修掉的两处测试自身缺陷

- e2e 里 `--offline` 互斥断言查 stdout，但 v2.1.1 起错误信息统一走 stderr → 改为合并检查
- 平台可用性断言绑定了 `exit in (0,2)`，而 `ima` 对不满足七字段的目标判 BLOCKED 是**正确行为**
  → 改为只验「未被当成未知平台拒掉」

**教训：测试断言写错时会伪装成代码缺陷。**这两处都不是代码问题，
但如果直接改代码去迎合测试，就会把正确行为改坏。断言必须对齐**意图**而非**当前实现**。

---

## [2.1.1] — 2026-10-08

**这一版修的是 v2.1.0 的三个阻断级漏洞 + 一个性能问题，全部由「对抗式审查」发现。**
它们共同的特点是：**不报错、门禁看起来在正常工作，实际上判据可以被改掉**。
常规的 clean code 审计一个都没抓到（详见文末「两条审查路线的分工」）。

### P0-1 · 配置不能放宽平台硬校验（阻断）

**漏洞**：`--config` 能把 BLOCKED 变成 PASS。实测 `{"spec":{"frontmatter":{"required":[],
"slug_pattern":".*"}}}` 使 FM-002 的两条硬校验（slug 格式、version SemVer）整体消失。
根因：方向性保护只有 `_LOWER_IS_STRICTER` 四个 bundle 字段，`frontmatter` 段完全裸奔。

**修法**：`FIELD_POLICY` 字段策略表，两档 + fail-closed
- `lower_only`：4 个包体阈值，只许调小
- `locked`：`frontmatter` 的 `required` / `slug_pattern` / `semver_pattern` / `slug_min` / `slug_max`，
  以及 5 个顶层清单字段
- **未登记字段一律拒绝**：防止「作者忘了登记某个字段」变成绕过口

顶层清单字段（`forbidden_files` 等）另有一条指路报错：它们不是段落、没有子键，
要用专门的 `forbidden_files_append`（只增不减）。此前实现把它们当 dict 处理，
攻击虽被挡住但报「必须是对象」——**错因不对会让人以为换个写法也许能过**。

### P0-2 · baseline 三连（阻断）

| 漏洞 | 实测 | 修法 |
|---|---|---|
| `--write-baseline` 无档位过滤 | 2 条 critical（凭据泄漏 + 封禁文件）写入后复跑直接 PASS | `write_baseline` 只接受非 blocker 项；基线文件新增 `skipped_blockers` 字段**自证**当时跳过了什么 |
| `--baseline X --write-baseline X` 同开 | 「基线抑制 1 条」→「已写入基线 **0 条**」，基线被清空 | 两参数同开直接 exit 2（语义上「用它筛」与「重新定义它」不该共存于一次调用） |

### P0-3 · `--strict` 必须真的锁死（阻断）

**漏洞**：`_has_overrides` 只检查 `spec` 与 `forbidden_files_append`，于是 `--strict` 下
`whitelist_append` 与 `rules_append` 仍放行——而白名单对**所有规则**生效（含 `RED-NET-*` 红线），
等于「锁死规则库」却仍可静音红线。

**修法**：
- `--strict` 拒绝全部四类覆盖键（含追加类）
- `rules_append` 拒绝 `level == "info"`：info 级命中不计入 verdict，
  允许「声明 critical 却永不阻断」就是给配置一把万能静音钥匙
- `whitelist_append` 加条数上限（20）与单条长度上限（200）
- `rules_append` 的 pattern 加长度上限（200）、条数上限（20）与**嵌套量词检测**
  （`(a+)+` 实测每多 4 字符耗时 16 倍，足以挂死门禁 = ReDoS）

### P0-4 · 性能：600 文件从 80 秒降到 4 秒（严重）

`cProfile` 显示 `_read` 被调 **56184 次**、`_io.open` 独占 49 秒。根因是 `check_rules` 在
「pattern × target × 行」三层循环里反复重开文件（135 pattern × 600 文件 = 81000 次），
且 4 个检查项各自遍历一遍 `os.walk`。**这个问题从 v1.x 就在**，本轮才因造了 600 文件暴露。

修法：`run_all` 开头一次性 `_prime_caches()` 填充文件清单与全部文本，`_read` 改查缓存。
实测 **80s → 4s**，代价是 tracemalloc 峰值 1.86 MB（600 个小文件，可忽略）。

### 验证

- **用原始攻击原样重打**（`_test_p0_verify.py`，14 项）：B1/B2/B3 三个原始攻击全部被挡住，
  且正例（干净 skill 的基线往返）未被焊死
- 模块单测新增 22 条**反向断言**（攻击被拒），不再只测「该拦的拦住」
- 既有 37 + 60 项断言全绿；四平台零回归（BLOCKED(2) / PASS / NEEDS_FIX(2)）

### 两条审查路线的分工（本次最大的方法论收获）

| 路线 | 判据 | 抓到了什么 |
|---|---|---|
| clean code 审计 | 读起来费不费劲 / 改起来怕不怕 | 结构债（重复遍历、同名不同签名、字段丢失） |
| 对抗式审查 | **能不能被绕过** | 3 个阻断 + 4 个严重的绕过问题，审计一项没抓到 |

**审计不能作为安全门禁版本的唯一放行依据**——它的判据里没有「可被绕过」这一维。

---

## [2.1.0] — 2026-10-06

**本轮做的是《优化方案（竞品对标版·v3）》里的 P0 全部七项 + `--platform ima`。**
方案里把这批叫「v1.5.0」，但 v2.0.0 已被上一版的定位升级 + 合并占用，
**版本号只能往前不能回退**，故落为 **2.1.0**（纯增量、无破坏性变更，符合 MINOR）。

### 缝接层：L0 与深度扫描器之间补上公共货币

| 能力 | 参数 | 说明 |
|---|---|---|
| SARIF 2.1.0 产出 | `--format sarif` | `$schema`/`version`/`runs[].tool.driver.rules+results`/`level` 映射/`region.startLine` 齐全，指纹写进 `partialFingerprints`（规范里存放跨运行稳定标识的位置，GitHub Code Scanning 会用它跟踪复发） |
| SARIF 导入 | `--sarif-in FILE` | 吃任意外部扫描器结果；畸形输入只跳过该条并记日志，不崩 |
| 统一指纹 | 自动 | `sha256(ruleId\|file\|line\|title)` 前 16 位。**刻意不含命中原文**——否则改一次文案就要重建一次基线 |
| 基线抑制 | `--baseline` / `--write-baseline` | 被抑制项降为 info 保留可追溯，不删除（否则基线成了无法审计的黑洞） |
| 外部配置 | `--config` / `--strict` | 阈值、封禁文件追加、自定义规则、白名单 |
| 外部扫描器 | `--deep-scan CMD` / `--offline` | `{dir}` 占位符替换；不经 shell；失败不影响本地判定 |

**两条不变量**（改这块前先看这段）：
1. **L2 finding 一律降一级**（critical→high），且一律不带 `redline`。依据是 LLM 语义层实测精度
   约 87%——把它的 critical 直接当 BLOCKER 会被误报轰炸，用户随后只会把工具关掉。
   `--sarif-trusted` 是唯一例外，且要调用方自己负责。
2. **深度层失败绝不影响 L0 判定**。扫描器不存在/超时/输出不合法，一律只记一条日志。
   已测：二进制不存在、退出码非 0、输出非 JSON、输出非 SARIF，四种情况 verdict 均与不带时一致。

### 能力补齐

- **C3 MCP 专项**（`MCP-PRIV-001` / `MCP-PROMPT-001` / `MCP-DECLARE-001`）：
  工具权限过宽（`permissions: "*"`、任意文件读写、跳过沙箱）、工具描述投毒（"不要告诉用户
  这次操作"、"调用前不要检查"）、提到 MCP 却未在 `requires` 声明（降 INFO，默认静音）。
- **C4 agentic 类目**（`AGENT-MEMORY-001` / `AGENT-LEAK-001` / `AGENT-AUTONOMY-001` /
  `AGENT-REFUSAL-001` / `AGENT-TRIGGER-001`）：记忆投毒、系统提示泄漏、过度代理权、
  反拒绝绕过、触发词滥用。**这是通用代码扫描器够不到的层**——它们不读 SKILL.md，
  抓不到指令式风险。
- **C1′ stdlib ast 薄兜底**（`ast_guard.py`）：动态执行、shell 解释执行、不安全反序列化、
  非安全 YAML 加载、动态导入，给精确行号。**不做污点追踪**——那是 Codex Security /
  SkillSpector 的主场，自己写是拿短板上别人的长处。
- **`--platform ima`**：frontmatter 七字段、包内零 `_meta.json`、ASCII 直引号、
  纯 ASCII 文件名、`trigger_keywords ≤5`。规则写在 `platform_profiles.ima`，
  **平台口径变了改 JSON 即可，不动 `gate.py`**。

### 规则引擎修复（都是被自家文档 dogfood 出来的）

1. **`SEC-PROMPT-001` 的 `DAN` 缺词边界**（v1.x 就存在的旧 bug）：
   `DAN\s*(模式|mode)?` 会把 `ast_guard.py`、`check_ast_dangerous_calls` 里的 "dan" 当成
   越狱模式命中。改为 `\bDAN\b`。**这是本轮修的第一个历史缺陷。**
2. **新增 `use_global_meta_markers` 开关**（默认 true）：全局 `META_MARKERS` 含「不要」「无需」，
   而 agentic 攻击句式本身就是「不要 X」「无需确认」——叠加后规则会自己废掉。
   9 条 agentic/MCP 规则显式关掉，改用自己的 `exclude_patterns` 精确豁免否定式表述。
3. **新增规则目录行豁免**（`_is_rule_catalog_row`）：文档里那张检查项表会命中自己写的规则。
   口径刻意收窄——必须**同时**满足 ① 以 `|` 开头（表格行）② 行内含本规则自己的 ID
   ③ 行内含档位词（BLOCKED/NEEDS_FIX…）。只满足一条不豁免，否则真违规排成表格就能溜过去。
   已验证：表格行但无档位词的攻击句仍被拦。
4. **`MCP-PRIV-001` 移除过宽的「示例」marker**：否则攻击句写「配置示例：permissions: "\*"」
   就能躲过去。

### 代码审计（skill-clean-audit 第一性原理审计，同日）

对本轮新代码做 A（理解成本）/ B（修改风险）两轴审计，**3 红 12 黄 7 绿**。红项已全部修掉：

| 红项 | 问题 | 修法 |
|---|---|---|
| 🔴 A1 | `sarif_io.from_sarif` docstring 承诺「畸形输入不抛异常」，实测 `message: null` / `properties: null` 直接 `AttributeError`，**整进程带 traceback 崩掉、L0 判定一个字都没输出**。根因是 `d.get(k, {})` 在「key 存在但值为 null」时返回 `None`——而这正是真实 SARIF 里最常见的形态 | 新增 `_as_dict` / `_as_text` 两个安全取值器，外部字段一律先过这一道；6 种 null 输入实测全不崩 |
| 🔴 B2 | `check_ima_compliance` 把 `os.walk` 生成器 `_iter_skill_files()` 放在**外层循环体内**，复杂度 O(禁用项数 × 全目录文件数) | 清单提到循环外取一次，(b)(c)(d) 三段共用 |
| 🔴 B1 | `SkillHubGate.apply_baseline()` 与 `sarif_io.apply_baseline()` **同名、不同签名、不同返回类型** | 前者改名 `suppress_baseline`（读文件在 gate、拆分在模块） |

另修三个高价值黄项：
- **B3**：`check_ast_dangerous_calls` 丢弃了 `ast_guard` 产出的 `why` 字段，安全报告里只剩
  「怎么改」没有「为什么危险」→ 已并入 `clause`。
- **B8**：`platform_profiles` 原放在 JSON 顶层，而 `_load_spec()` 只返回 `spec` 子树 →
  `check_ima_compliance` 恒为 None、**ima 检查静默全跳过**（不报错，只是没检查）。
  已挪进 `spec` 子树，并在顶层加 `layout_note` 说明布局约定。
- **A6**：`ast_guard.GuardResult` 的 docstring 里写着「后者是审计必挑的点」——
  在源码里预告审计意见属自指式注释，读者会以为「已经审过了」，已改为就事论事的说明。

> 审计的一条结论值得单独记：**这三个红项里有两个（A1、B8）的失败模式都是「静默」**——
> 一个崩在缝接层让整个门禁没输出，一个让整档检查悄悄不跑。门禁这类工具最危险的失败
> 不是误报，是静默失效。后续加检查项时，「不报错」不等于「检查到了」。

### 跨平台 bug 修复（Windows）

- **`shlex.split` 吃反斜杠**：`--deep-scan` 命令里的 Windows 路径 `C:\Users\...\x.py` 会被
  按 POSIX 转义规则拆成 `C:Users...x.py`，扫描器静默不生效。改为先归一化为正斜杠再拆词。
- **路径含空格时引号被吃**：`posix=True` 会剥掉引号，`AppData\Local\Temp` 这类路径必中。
  改用 `posix=False` + 自剥一层引号（只剥首尾配对的那层，否则 `it's` 会被削成 `t`）。
  文档已写明含空格必须加引号。

### 自反与回归（已实测）

- **三平台零回归**：skillhub BLOCKED(2) / github PASS / clawhub NEEDS_FIX(2)，与 v2.0.0 完全一致。
- **门禁抓到本轮自己写的代码注释**：为解释 shlex bug 而写的 `C:\Users\me\x.py` 示例被
  `PRIV-PATH-001` 判为绝对路径泄漏——规则判得对，改的是注释不是规则。
  这与 v2.0.0 那次「检查项表写 GPL/AGPL 被 `OSS-COPYLEFT-001` 拦」是同一个教训。
- **验证方式**：37 项模块单测 + 60 项端到端 fixture 全部通过，含正反两面
  （该拦的拦住、该豁免的豁免、带/不带 `--deep-scan` 的 L0 结论一致性）。
  **不以「跑起来没报错」当通过。**

---

## [2.0.0] — 2026-10-06

**定位变更**：从「SkillHub 发布前本地门禁」扩展为 **「Skill 发布门禁（代码安全 + 平台规范 + 内容措辞）」**。
合并对象：**ai-weekly-publish-gate**（国内平台措辞红线 + `--learn` 回灌闭环）。
原 ai-weekly-publish-gate 目录保留但改为重定向说明，能力不再依赖外部仓库的 `compliance_check.py`。

**更名 skillhub-gate → skill-publish-gate**（同一次发布内完成，属 breaking）
- 代码 / CLI / 退出码 / 规则库 / tag 序列（`v1.0.0`~`v1.4.0`）全部不变，仅是技能身份不再绑定单一平台。
- 前称 `skillhub-gate` 保留在 frontmatter description、`use_when`、`trigger_keywords`、
  README 迁移段与本报告历史条目中，便于从旧名检索回来。
- 规则库文件名仍为 `rules/skillhub-spec.json`（改名会牵动脚本内路径常量与发布包结构），
  其 `description` 已显式声明与新名对齐。

**新增规则 RED-NET-005（措辞红线扩展，来自 2026-09-22 ai-weekly 文档措辞下架事故）**
- 扩展词表：`防火墙` / `v2board` / `sspanel` / `clashx`（此前门禁只覆盖到 clash 主名与部分同族词）。
- 违规叙事正则（此前完全缺失，或只覆盖字面量、漏变体）：
  `绕过.{0,12}(限制|反爬|封禁|封锁|网络管理)`、`突破.{0,12}(封锁|限制)`、
  `解决.{0,10}(访问|连接)不了`、`走通.{0,20}(即可|就能).{0,10}恢复`。
- 与既有 `RED-NET-001~004` 做了去重交叉验证：`免翻墙`（001 裸词已覆盖）、`提升.{0,20}可达性`
  与 `恢复.*访问`（004 已覆盖）**不重复收录**，避免同一行双报。
- clawhub 模式同样通过 `platform_downgrade` 降级为 WARN，与 001~004 口径一致。
- 逐条验证：8 条 pattern 全部实测命中（fixture 8/8），且不误伤合规自描述行。

**发布产物卫生项并入 forbidden_files（规则 FORB-001，BLOCKED）**
- 新增 `.github_token` / `.workbuddy` / `.env` / `.venv` / `node_modules` 五项——
  之前只有 `.gitignore`、`.nojekyll`、`.pytest_cache` 等被拦，凭据文件与虚拟环境目录是盲区。
- clawhub 模式随封禁文件检查一并跳过（ClawHub 不按文件类型挑）。

**平台口径补齐**
- `--platform github` 此前无文档示例，v2.0.0 加入 SKILL.md / README 用法节。
- README / SKILL.md 的分工表显式化：与 `skill-compliance-check`（国内监管合规）、
  CodeQL/Semgrep/domsec（工业级源码审计）、gitleaks（专用密钥）、平台安全扫描（VirusTotal/LLM 评估）
  的边界写清，避免本门禁被当深层审计工具硬套。

**自反与回归（已实测）**
- 修掉一处新引入的自误伤：检查项表原写「GPL/AGPL/SAGPL」，被自家 `OSS-COPYLEFT-001`
  判成携带传染性协议；改为「copyleft 家族」并注明协议名见规则库。
- `--platform skillhub` 自家：BLOCKED（`.gitignore` + `LICENSE` 封禁，预期，与 v1.4.0 一致）；
  `--platform github`：PASS；`--platform clawhub`：NEEDS_FIX（2 条预期 WARN）。
  三平台行为与 v1.4.0 完全对齐，**无回归**。
- fixture 验证：凭据文件 / 未钉版依赖 / 新措辞规则均如期 BLOCKED，无「写了不生效」的假规则。

**版本号**：SKILL.md frontmatter `1.4.0` → `2.0.0`（含 `spec_version` 同步）。

## [1.4.0] — 2026-10-03

新增 `--platform clawhub` 模式，使本门禁可兼任 ClawHub 发布前本地门禁（复用 + 翻转 + 补齐）。

**复用（clawhub 模式仍为 BLOCKER，是各平台安全扫描的本地映射）**
- 恶意代码 / 持久化篡改 / Prompt 注入 / 凭据泄漏 / PII 泄漏 —— 三项 P0 安全检查不变。

**翻转降级（SkillHub 专属口径，ClawHub 不认）**
- 封禁文件检查在 clawhub 模式整体跳过（ClawHub 接受任意扩展名，`.gitignore`/`.github` 等不再拦）。
- 翻墙词族 `RED-NET-001~004` 通过规则引擎新增的 `platform_downgrade` 钩子，在 clawhub 模式
  由 BLOCKER（critical/high）降级为 WARN（ClawHub 不做关键词内容审核）。
- `platform_downgrade` 钩子对所有规则通用：规则 JSON 加 `"platform_downgrade": {"clawhub": "medium"}` 即可按平台降级。

**补齐 ClawHub 特有两检（当前门禁原本没有）**
- `LICENSE-FIELD-001`：frontmatter 声明 `license:` 且非 `MIT-0` → BLOCKED（ClawHub 强制 MIT-0）；
  声明为 `MIT-0` → WARN（建议移除该字段）。
- `META-MISMATCH-001`：脚本调外部 CLI/子进程/网络但 frontmatter 未声明 `requires` → WARN
  （ClawHub 标志性的声明-内容一致性审核）。

**自反与回归**
- 自反 WARN 属预期：本技能 frontmatter 含 `license: MIT-0`，clawhub 模式跑自身会触发
  `LICENSE-FIELD-001` + `META-MISMATCH-001`（均 WARN，不阻断）；skillhub/github 两模式行为零变化。
- 版本号 1.3.1 → 1.4.0（SKILL.md frontmatter + rules/skillhub-spec.json 同步）。

## [1.3.1] — 2026-10-02

文档质量打磨（对照 CSDN《Skill 质量评估》8 维度框架的 D1/D2/D5 扣分点），无逻辑变更：

- **D1 元数据质量**：新增「适用范围与边界」一节，显式列出不适用场景
  （发 ClawHub / 运行时监控 / 纯内容合规审计 / 当审核保证），让触发更精准、减少误用。
- **D2 执行引导**：补充「目录合法性」说明——`--dir` 指向不存在或不含 `SKILL.md` 的目录时
  报 `FM-001`（critical / BLOCKED，exit 1），不静默放行也不崩溃。
- **D5 输入输出**：补充 `--format json` 的完整输出字段契约（verdict/issues/info_hits 结构）
  与 `--output` 覆盖行为，便于接入 CI / 后处理。
- 版本号 1.3.0 → 1.3.1（SKILL.md frontmatter + rules/skillhub-spec.json 同步）。
- 修复：`--platform github` 模式下把 `.gitignore` 加入 `github_allowed_files` 豁免列表
  （GitHub 开源仓库的标配文件，不应被门禁自身 dogfood 误拦；SkillHub 默认模式仍照常拦截）。

## [1.3.0] — 2026-09-26

对照《腾讯 SkillHub 服务协议》（2026-07-20 生效）补齐 P0 安全风险扫描，每条问题标注协议条款出处：

- 新增 `SEC-PERSIST-001`（critical）：检测 Skill 指示宿主**永久**篡改持久化身份/记忆文件
  （SOUL.md/MEMORY.md/IDENTITY.md/USER.md）——文档命令式指令 + 脚本实际写调用双路，
  防御性元语境（不得/不修改/本门禁）跳过，避免误伤门禁自身说明。
- 新增 `PRIV-PII-001`（high）：扫描身份证（18 位校验位）、手机号、银行卡/账号（Luhn 校验）；
  命中值脱敏回显 `[REDACTED_PII]`，占位符/元语境自动跳过；三类 PII 独立上报。
- 新增 `SEC-PROMPT-001`（high）：Prompt 注入特征（忽略之前指令 / 越狱 / DAN）；
  技能在描述防御注入（带防护元语境）时不报。
- 新增 `SEC-MALWARE-001`（critical）：恶意代码模式（eval/exec 执行 base64、下载即执行、
  反向 shell、rm -rf / 等），防御性元语境跳过。
- 新增 `OSS-COPYLEFT-001` / `OSS-STRIP-001`（high）：开源传染性协议（GPL/AGPL/LGPL）
  与版权剥离检测（只扫文档，避免误伤门禁自身检测正则）。
- 凭据特征扩容（协议 5.1/5.4）：新增私钥块 / SSH 凭证 / 数据库连接串 / 高熵明文赋值。
- `PRIV-NAME-001` 排除公开笔名 `Elisabeth15501`，避免把已选定的笔名当真名泄漏。
- 规则引擎透传 `clause` 字段，文本报告新增「依据：第 X 条」，可回溯协议原文。
- 自测：`--platform github` dogfood = PASS（零误报）；恶意样例 6 类 P0 全部命中。

## [1.2.0] — 2026-09-25

为「只 GitHub 开源」分发策略解决 LICENSE 冲突，并系统化跨平台预检：

- 新增 `--platform {skillhub,github}`：默认 `skillhub`（LICENSE 等是封禁 BLOCKER）；
  `github` 模式下 `LICENSE`/`LICENSE.md`/`LICENSE.txt`/`.github` 豁免（开源许可文件合法）。
  `dirs` 子命令同步支持 `--platform`。
- 新增 `LICENSE` 文件（MIT-0）+ SKILL.md `license: MIT-0`，门禁作为 GitHub 开源项目版权完备。
- 门禁对自身：`--platform github` 模式 dogfood = PASS（带 LICENSE）；
  默认 `skillhub` 模式会拦 LICENSE（提示「若发 SkillHub 需先移除」），符合跨平台各出副本。

## [1.1.0] — 2026-09-25

对标 ai-weekly-publish-gate（源于 ai-weekly 被下架教训）补齐三块能力：

- 回灌闭环 `--learn`：发布后审核发现写回 `rules/feedback.json`
  （`learned_blockers` 追加为额外 BLOCKER、`learned_warns` 为额外建议、
  `whitelist` 命中静音）。私有白名单只静音确认过的误报，防复发不哑真问题。
- 凭据泄漏 SECRET 检查：扫描 ghp_/sk-/AKIA/glpat-/xoxb-/AIza/ya29 等特征，
  命中一律脱敏回显 `[REDACTED_SECRET]`，绝不把密钥写进日志/CI 输出（二次泄漏防护）。
- INFO 级默认静音：`--show-info` 才显示出站代理等需人工确认定位的命中；不影响 verdict。
- `--git` 默认集：目录自身是 git 仓库时只扫 `git ls-files`（等价发布所见），
  `--all-files` 强制全扫；依赖钉版 WARN（requirements.txt）。
- SKILL.md/README 补「三条铁律」（功能合法 ≠ 文档合规 / --proxy 定位内网 /
  降级而非绕行）与回灌用法。

## [1.0.0] — 2026-09-25

- 初版：SkillHub 发布前本地门禁。
- 检查项：frontmatter 真 YAML 解析 + 必填字段硬校验、封禁文件类型、包体上限、
  版本一致性、网络声明一致性、内容审核红线（网络规避敏感词 / 绕过网络管理叙事 /
  绝对化用语 / 金融敏感表述）、隐私泄漏、权限声明。
- 双轨判定 PASS / NEEDS_FIX / BLOCKED，退出码 0 / 2 / 1，可作 CI gate。
- 规则数据外置 `rules/skillhub-spec.json`，元语境豁免避免合规/安全类技能自描述误报。
- 对标 skill-compliance-check 结构，聚焦 SkillHub 平台规范。
