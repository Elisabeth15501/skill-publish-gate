# 第一性原理 Clean Code 审计 · skill-publish-gate/scripts

> 方法论：`skill-clean-audit`（理解成本 A / 修改风险 B，红黄绿三档）。
> 根前提：**代码是写给人看的**——只有两根判据：A. 让人一眼读懂意图与边界；B. 改动时不牵连出错。
> 本审计**只读**，不修改被审代码。指标命中≠脏：能用「注释说清 + 范围可控」解释且真降成本的，归绿/黄而非红。

## 表头（审计对象）

| 文件 | 行数 | 定位 | 修改频率 |
|---|---|---|---|
| `scripts/gate.py` | 1843 | 主检查器 + CLI（15 项检查 + 缝接层 + 回灌闭环 + argparse） | 高（每次加规则/平台都动） |
| `scripts/config_loader.py` | 341 | 外部配置加载（只许更严的字段策略） | 中 |
| `scripts/sarif_io.py` | 517 | SARIF 2.1.0 双向编解码 + 指纹 + 基线 | 低（OASIS 标准固定） |
| `scripts/ast_guard.py` | 248 | stdlib-ast 危险调用薄兜底 | 低 |
| `scripts/gen_en_docs.py` | 637 | 英文版文档生成器（共享源+注入不变量） | 中 |

探针（`metric_probe.py`，只提示不判级）命中：gate.py 61 条 / sarif_io.py 9 条 / config_loader.py 7 条 / ast_guard.py 3 条。

---

## 审计结论（先看这里）

**整体评级：绿为主，无红项。** 这套代码在可读性上投入远超多数 CLI 工具——几乎每个非显然决策都带「为什么」注释，A（理解成本）轴显著偏低。真正的债集中在 **B（修改风险）轴**，且全部是「黄」级（注释说清 + 范围可控），按 Boy Scout 原则**不主动还债，等下次自然触达再清**。

「脏」偏在哪一侧：**偏 B（修改风险）**，不是 A。具体是 gate.py 的「集中式判定核心 + CLI 编排函数过长、深嵌套」，以及 sarif_io 的「指纹身份键三处平行定义」。但债的「质量」很高——都有 docstring 解释 why，所以不构成红。

---

## A. 理解成本表（A 轴）

| # | 信号 | 命中 | 证据(行) | 说明 |
|---|---|---|---|---|
| A1 | 长函数（>40 行） | ✅黄 | gate `cmd_check` L1547（105 行）·`cmd_dirs` L1691（81）·`report` L1244（78）·`main` L1774（66） | 都是「编排型」函数：把子步骤顺序串起来，内聚但长。注释已说清意图 → 黄 |
| A2 | 深嵌套（≥4） | ✅黄 | gate `check_rules` L599（深 10）·`check_pii_leak` L861（深 10）·`report` L1244（深 10）·`check_clawhub_compliance` L958（深 10） | 嵌套深度来自「pattern×target×行」扫描循环，是算法本性。读者需脑内维护 3-4 层上下文 → 黄 |
| A3 | 参数数 ≥4 | ✅黄 | gate `_add` L214（11 参）·`__init__` L164（6 参）·sarif `fingerprint` L92（5 参）·`save_baseline` L463（4 参） | `_add` 是「构造一条 issue」的宽签名，每个参数语义清晰（category/severity/file/line/found/recommendation…），调用处虽长但可读。`__init__` 6 参含 2 个布尔旗 → 黄 |
| A4 | 布尔旗参数 | ✅黄 | gate `__init__(use_git, strict)` L164 ·`_add(redline=)` L214 ·`run_all(show_info=)` L1136 ·`_add_shared_scan_args(with_baseline=)` L1654 ·`from_sarif(trusted=)` L316 ·sarif/`apply_config(strict=)` | 多为「同一函数两种相反行为」。`use_git`/`strict`/`show_info`/`trusted` 语义自解释，注释补齐 → 黄 |
| A5 | 命名即文档 | ❌未命中（好） | 全模块 | `_prime_caches`/`_strip_source_prefix`/`assign_occurrences`/`_is_rule_catalog_row` 等命名精确表达意图，A 轴干净 |
| A6 | 注释解释「为什么」 | ❌未命中（好） | 全模块 | 「对抗式审查 M1/S2/S3/G1-G4/B1-B3」等注释把每个非显然决策的根因写清，是本项目最强的可读性资产 |
| A7 | 注释退化成 changelog | ❌未命中 | — | 工单号注释都带「为什么这么做」，不是裸 changelog |

**A 轴小结**：无红。黄项集中在 gate.py 的「长编排函数 + 深扫描嵌套 + 宽签名」，但都被 A5/A6 的命名与注释对冲掉了大半理解成本。

---

## B. 修改风险表（B 轴）

| # | 信号 | 命中 | 证据(行) | 说明 |
|---|---|---|---|---|
| B1 | 同类逻辑重复 ≥3 | ✅黄 | sarif `dedupe` L408 与 `apply_baseline` L486 都调 `assign_occurrences`（正确做法）；但 `issue_identity` L140 / `sarif_io_key` L153 / `fingerprint` L92 三条「身份键」平行存在 | 三键各管「去重 / 基线 / 测试」，docstring 已划清边界 → 黄。风险：改指纹口径要同步改三处，漏一处即跨工具去重失效 |
| B2 | 重复逻辑（check 内） | ✅黄 | gate `cmd_check` 与 `cmd_dirs` 的「构造 gate + 注入 config_whitelist + run_all + 缝接层」序列几乎平行（L1585-1641 vs L1729-1747） | 两个子命令各写一遍，G3 注释已记「手抄漂移」教训。新增缝接层能力要改两处 → 黄 |
| B3 | 布尔旗导致「双行为」 | ✅黄 | gate `__init__` 的 `use_git`/`strict`；`from_sarif(trusted)` 的「封顶/不封顶」两路 | 改默认值或加新旗时易漏掉对称分支 → 黄 |
| B4 | 单文件内规则清单与 spec 双源 | ✅黄 | gate `CREDENTIAL_PATTERNS` L1329 硬编码 vs `rules/skillhub-spec.json` | 安全类 9 条凭据特征写死在 gate，平台类走 spec。加新凭据格式只改 gate，但「为何这条在 gate 不在 spec」的边界需读者记住 → 黄 |
| B5 | 长函数内部多职责 | ✅黄 | gate `cmd_check` L1547 内含「回灌 / 路径校验 / 平台解析 / 互斥检查 / 缝接层 / 基线 / 报告」7 段职责 | 各段有注释分隔，但函数体 105 行，改某段（如基线互斥）需通读上下文 → 黄 |
| B6 | 宽签名 `_add` | ✅黄 | gate `_add` L214（11 参） | 新增 issue 字段要改签名 + 全部 ~15 处调用点 → 黄 |

**B 轴小结**：无红。黄项都是「结构性平行 + 集中式核心」，已有注释标注边界，风险可控。最值得关注的是 B1（指纹三键）与 B2（check/dirs 平行编排）——它们是真会「改一处忘一处」的点。

---

## 额外发现（清单外，同属理解成本）

- **gate.py 的 `SkillHubGate` 是个「上帝类」倾向**：一个类承载了 YAML 解析、文件缓存、15 项检查、缝接层、判定、报告、CLI 之外的所有职责（L163-1321，1150+ 行）。这是 B 轴最大来源——但拆类是「无人碰代码就净亏」的重构，当前有测试兜底，维持现状合理。
- **`_fm_data` 哨兵**：`check_frontmatter_required` 等靠 `hasattr(self, "_fm_data")` 判「上一步是否 BLOCKER」（L370、L518、L549）。哨兵靠「上一步是否成功」隐式传递，加新检查时容易忘。建议改显式 `self._fm_data_ok: bool`（黄，B 轴）。
- **`gen_en_docs.py` 的巨型模块级字符串常量**：`SKILL_EN`/`README_EN`/`RULE_CATALOG_EN`/`CLI_REFERENCE_EN` 各 80-180 行内嵌在 .py 里。这是「翻译文本」放对了地方（与数据源分离），但单文件 637 行偏长。可接受（黄，A 轴，纯文本无逻辑）。

---

## 审计评分

| 档 | 数量 | 落点 |
|---|---|---|
| 🔴 红 | **0** | — |
| 🟡 黄 | **A1-A4（4）+ B1-B6（6）= 10** | 偏 B（修改风险）轴为主 |
| 🟢 绿 | 命名/注释/职责边界/测试覆盖 | 显著强项 |

---

## 修复优先级（Boy Scout：正在被改的文件才顺手清）

按「先消零行为风险的纯可读项，再排重复/拆函数，黄项随改顺手处理」：

1. **现在不动**：B1（指纹三键）/ B2（check/dirs 平行）/ 上帝类——都有测试兜底且无 bug，提前重构净亏。仅当**真要改指纹口径或加缝接层能力**时，顺手把序列抽成共享 `_run_gate_pipeline()`。
2. **顺手清（零行为风险，纯可读）**：
   - B5：`cmd_check` 把「回灌 / 路径校验 / 平台解析 / 互斥」各段抽成 `_handle_learn` / `_validate_dir` 等小函数，105→40 行内。
   - `_fm_data` 哨兵改 `self._fm_data_ok` 显式布尔，消除隐式耦合。
3. **保持现状**：A 轴所有黄（长函数/深嵌套/宽签名）——命名与注释已对冲理解成本，强拆反而抬升 B。

> 本 skill 只读不改。以上优先级是建议；落地修复请另开一轮 Agent 任务，按 SemVer 走 MINOR（v3.2.0）。

---

## v3.2.0 顺手清记录（本审计的交付落地点）

按上表优先级，v3.2.0 落地了「顺手清」档的全部可执行项（零行为风险，8 个测试模块全绿兜底）：

| 审计项 | 处置 | 落点 |
|---|---|---|
| **B4** | ✅ 已清 | `CREDENTIAL_PATTERNS` 加注释说清「代码安全轴 vs 平台规范轴」边界 + 只增不减红线 |
| **B5** | ✅ 已清 | `cmd_check` 拆成 6 个小函数（`_handle_learn` / `_validate_dir_and_platform` / `_build_and_run_gate` / `_load_shared_sarif` / `_apply_baseline_stitching` / `_run_stitching`），主函数 ~30 行 |
| **B2** | ✅ 已清 | 上述 helper 同时被 `cmd_check` 与 `cmd_dirs` 复用，缝接层不再手抄两遍（`write_baseline` 用 `getattr` 兜底 dirs 未注册） |
| **`_fm_data` 哨兵** | ✅ 已清 | `hasattr(self, "_fm_data")` 隐式耦合 → 显式 `self._fm_data_ok: bool` |
| B1（指纹三键） | ⏸ 故意不动 | 改指纹口径时才顺手清，当前有测试兜底无 bug |
| A 轴长函数/深嵌套/宽签名 | ⏸ 故意不动 | 命名+注释已对冲理解成本，强拆抬升 B 轴 |

**结论**：审计时 0 红 / 10 黄，本轮清掉其中 4 个黄项（B4/B5/B2 + 哨兵），剩余黄项均为「主动重构净亏」类，维持现状合理。
