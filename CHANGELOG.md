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
