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
