---
name: skillhub-gate
slug: skillhub-gate
version: 1.3.0
displayName: SkillHub 发布前本地门禁
summary: 发布到 SkillHub 前本地跑一遍，拦掉会被拒/卡死/下架的规范问题
tags: [skillhub, 发布门禁, 合规预检, preflight, 上架检查]
license: MIT-0
description: >-
  SkillHub 发布前本地门禁（preflight gate）。在 `skillhub publish` 之前对目标
  skill 目录做规范预检，拦掉三类真实失败：① frontmatter 硬校验（slug/version/
  displayName 缺失或不合法、YAML 静默解析失败）；② 封禁文件类型与超大产物包
  （.gitignore/.nojekyll/LICENSE/__pycache__/*.pyc/.github 会令正式发布报 400，
  文件数 >1000 会卡死）；③ 内容审核红线（网络规避敏感词、把功能描述成绕过网络
  管理限制、绝对化宣传用语、需资质的金融类表述）与隐私泄漏、权限声明缺失；
  ④ 安全风险扫描（对照《腾讯 SkillHub 服务协议》第 5.1/5.4/5.6、第 2.3、第 6.2 条）：
  持久化文件篡改、身份证/手机/银行卡等 PII 泄漏、Prompt 注入、恶意代码模式、
  开源传染性协议与版权剥离。每条问题均标注协议条款出处。
  对标 skill-compliance-check 的结构（脚本 + 规则 JSON + 子命令），但聚焦
  SkillHub 平台规范。退出码 0=PASS / 2=NEEDS_FIX / 1=BLOCKED，可直接当 CI gate
  或 pre-publish hook 使用。
use_when:
  - 准备 `skillhub publish` 之前想先本地预检，避免被服务端拒或卡死
  - 检查 SKILL.md frontmatter 是否会被 SkillHub CLI 静默解析失败
  - 批量检查多个待发布 skill 的规范状况
  - 想确认文档是否踩了内容审核红线（网络规避敏感词、绝对化用语、金融敏感表述）
trigger_keywords:
  - skillhub 门禁
  - 发布前检查
  - 发布预检
  - skillhub gate
  - 上架前检查
  - publish gate
  - preflight
  - 发布门禁
environment: local
network: none
dependencies: PyYAML（python -m pip install pyyaml；脚本缺失时自动尝试安装）
disclaimer: 本门禁仅做本地规范预检，不构成 SkillHub 审核保证。最终能否上架由 SkillHub 三线审核决定，责任由开发者自行承担。
---

# SkillHub 发布前本地门禁（skillhub-gate）

## 它解决什么

`skillhub publish` 有两个让人头疼的特性（已在 skillhub-publish 技能里反复验证）：

- `--dry-run` **只校验 frontmatter**，封禁文件类型要等正式发布才报 400；
- 仓库目录混入测试产物（allure-results / .pytest_cache / data 等）会让发布包
  上万 part，服务端处理时**卡死无输出**；
- 内容审核是三线并行（内容合规过滤 + 深度漏洞扫描 + 模型安全评估），文档里
  的网络规避敏感词、绝对化用语、金融敏感表述会直接拒或下架。

本门禁把这些**发布前就该发现的问题**一次性本地跑出来，并给 PASS / NEEDS_FIX /
BLOCKED 三档结论 + 退出码，能直接接 CI 或发布脚本。

## 检查项

| 类别 | 检查内容 | 触发后果 |
|------|----------|----------|
| FRONTMATTER 合法性 | 用真 `yaml.safe_load` 解析，抓半角「冒号+空格」等静默失败 | BLOCKED |
| 必填字段 | `slug`(kebab-case 2–128) / `version`(SemVer) / `displayName` | BLOCKED |
| 推荐字段 | `name` / `description` / `summary` / `tags` | NEEDS_FIX |
| 封禁文件 | `.gitignore`/`.nojekyll`/`LICENSE`/`__pycache__`/`*.pyc`/`.github`/`.clawhubignore` | BLOCKED |
| 包体 | 文件数 / 总体积超阈值（卡死风险） | BLOCKED / NEEDS_FIX |
| 版本一致性 | `version` 在 SKILL.md/config.json/metadata.json/CHANGELOG.md 是否统一 | NEEDS_FIX |
| 网络声明 | 声明 `network: none` 但脚本含真实网络调用 | NEEDS_FIX |
| 内容红线 | 网络规避敏感词、绕过网络管理叙事、绝对化用语、金融敏感表述 | BLOCKED / NEEDS_FIX |
| 隐私泄漏 | 绝对路径 / 真实用户名 / 真实量测值 | NEEDS_FIX |
| 权限声明 | 脚本含写文件/子进程/网络但 SKILL.md 无权限声明（对症 T 红线过度授权） | NEEDS_FIX |
| 凭据泄漏 | 疑似 token/key（ghp_/sk-/AKIA/glpat-/xoxb-/AIza 等），命中一律脱敏回显 | BLOCKED |
| INFO 级 | 出站代理提及（--proxy/HTTPS_PROXY），默认静音，需人工确认定位为内网出网 | 不阻断 |

> 元语境豁免：当命中词出现在「否定 / 定义 / 清单 / 说明」语境（如「检测网络规避
> 敏感词」）时视为自描述，不误报——所以合规/安全类技能罗列规则词不会被自己标红。

## 执行逻辑

触发后调用 `scripts/gate.py`：

```bash
# 单技能门禁（默认 text，退出码 0/2/1）
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
# 回灌：发布后审核发现的新坑写回 rules/feedback.json（防复发核心）
python scripts/gate.py check --dir <skill目录> --learn '{"type":"blocker","pattern":"新危险词","reason":"平台审核打回：..."}'
python scripts/gate.py check --dir <skill目录> --learn '{"type":"whitelist","pattern":"企业内网出站","reason":"已确认定位为内网场景"}'
python scripts/gate.py check --dir <skill目录> --learn '{"type":"warn","pattern":"某弱建议表述","reason":"..."}'
```

判定与退出码：

- `BLOCKED`（exit 1）：命中 blocker（frontmatter 硬校验失败 / 封禁文件 / YAML 解析失败 / 内容红线 redline）→ **必须修**。
- `NEEDS_FIX`（exit 2）：仅建议项（medium/low）→ 建议修，不阻断。
- `PASS`（exit 0）：无问题 → 可发布。

规则数据集中在 `rules/skillhub-spec.json`，新增/调整红线直接改 JSON 即可，不用动脚本。

## 与 skill-compliance-check 的分工

`skill-compliance-check` 偏「国内监管合规」（金融/广告法/隐私法律依据）；本门禁偏
「SkillHub 平台规范」（CLI 硬校验字段、封禁文件、包体、审核三线红线、可发布的工程
门禁）。两者可串联：`gate.py` 管发布前能不能发，`compliance` 管发上去合不合规。

## 发布前自检清单（给本技能自己）

1. `python scripts/gate.py check --dir .` 应为 PASS；
2. 用 `git archive HEAD` 导出干净副本再发布，别 `publish .` 仓库目录；
3. 不写 `license:` 字段（避免踩 ClawHub 强制 MIT-0 的明文禁令，跨平台各出副本）。

## 回灌闭环（防复发核心）

发布后若平台审核又暴露新坑，用 `--learn` 把发现写回 `rules/feedback.json`：

- `{"type":"blocker","pattern":"...","reason":"..."}` → 追加为额外 BLOCKER 规则（下次扫描即拦）；
- `{"type":"warn","pattern":"...","reason":"..."}` → 追加为额外建议项；
- `{"type":"whitelist","pattern":"...","reason":"..."}` → 加入白名单，命中即静音（只静音你确认过的误报，绝不哑掉真问题）。

下次扫描自动加载：`learned_blockers`/`learned_warns` 作为增量规则，`whitelist` 命中即跳过。
**私有白名单 = 只静音确认的误报**，不污染默认规则库，也不会哑掉真实红线。
这是把「一次下架教训」固化为「下次自动防复发」的关键机制（源于 ai-weekly 被下架的教训）。

## 三条铁律（踩过的坑）

1. **「功能合法」≠「文档合规」**：技能功能可能完全合法，但一句「提升海外源可达性」
   就会被判违规。文档里绝不出现法律含义明确的敏感词，更不把功能描述成「解决某类访问限制」。
2. **`--proxy` 的正确写法**：定位为「企业内网要求所有出站流量经统一代理」的通用 HTTP 参数，
   明写「仅用于合法的企业内网出站场景，不提供也不支持任何规避网络管理措施的能力」。
3. **降级而非绕行**：海外源不可达时，既定行为是降级到国内源 + 离线快照 + 如实标注，
   而不是「配代理恢复访问」。
