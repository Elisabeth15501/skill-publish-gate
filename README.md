# skillhub-gate · SkillHub 发布前本地门禁

[![license: MIT-0](https://img.shields.io/badge/license-MIT--0-blue.svg)](LICENSE)

`skillhub publish` **之前**本地跑一遍，拦掉会被服务端拒绝、卡死或下架的规范问题。
对标 [skill-compliance-check](https://github.com/) 的结构（脚本 + 规则 JSON + 子命令），但聚焦 SkillHub 平台规范。

> 本项目以 **MIT-0** 在 GitHub 开源，可自由克隆 / 接 ClawHub import。门禁本身的价值，
> 是给「准备发布到 SkillHub 的技能」做发布前预检——它解决的就是发布者最易踩的坑。

## 为什么需要它

- `skillhub publish --dry-run` 只校验 frontmatter，**封禁文件类型要等正式发布才报 400**；
- 仓库混入测试产物（`allure-results` / `.pytest_cache` / `data`）会让发布包上万 part，
  服务端处理时卡死无输出；
- 内容审核三线并行，文档里的网络规避敏感词、绝对化用语、金融敏感表述会拒或下架。

门禁把这些「服务端才暴露」的失败，提前到本地一条命令看出来。

## 安装

```bash
# 方式 A：克隆到 WorkBuddy 技能目录
cd ~/.workbuddy/skills
git clone https://github.com/<你>/skillhub-gate.git

# 方式 B：对话里一句话装（已连 GitHub 连接器时）
# 帮我安装这个 skill：https://github.com/<你>/skillhub-gate

# 方式 C：从 GitHub 导入 ClawHub（clawhub.ai → import → 填仓库地址）
```

依赖：PyYAML。脚本缺失时自动尝试 `pip install pyyaml`；仍不可用则作为 BLOCKED 报错，
**不会在无法 faithful 解析时放行**。

## 快速开始

```bash
# 单技能门禁（默认 skillhub 平台：LICENSE 等是封禁 blocker）
python scripts/gate.py check --dir <skill目录>

# 开源副本预检（github 平台：LICENSE 等许可文件豁免，仍查其余红线）
python scripts/gate.py check --dir <skill目录> --platform github

# ClawHub 预检（接受任意扩展名；翻墙词族降级为 WARN；补 MIT-0/requires 一致性检查）
python scripts/gate.py check --dir <skill目录> --platform clawhub

# 机器可读 / 落盘
python scripts/gate.py check --dir <skill目录> --json
python scripts/gate.py check --dir <skill目录> --output gate-report.txt

# 批量汇总（父目录下所有含 SKILL.md 的技能）
python scripts/gate.py dirs --dir ~/.workbuddy/skills
```

退出码：`0`=PASS，`2`=NEEDS_FIX，`1`=BLOCKED。可直接接 CI / pre-publish hook。

## 检查项一览

| 类别 | 内容 | 后果 |
|------|------|------|
| FRONTMATTER | 真 YAML 解析 / `slug`+`version`+`displayName` 必填 | BLOCKED |
| 封禁文件 | `.gitignore`/`.nojekyll`/`__pycache__`/`*.pyc`/`.clawhubignore`/`.pytest_cache` 等（SkillHub）；`LICENSE` 等仅在 `--platform skillhub` 拦，`--platform github` 豁免 | BLOCKED |
| 包体 | 文件数 / 体积超阈值 | BLOCKED / NEEDS_FIX |
| 版本一致性 | 多处 `version` 是否统一 | NEEDS_FIX |
| 网络声明 | `network:none` 与脚本实际调用是否一致 | NEEDS_FIX |
| 内容红线 | 网络规避敏感词、绕过网络管理叙事、绝对化用语、金融敏感表述 | BLOCKED / NEEDS_FIX |
| 隐私 / 权限 | 绝对路径泄漏、权限声明缺失 | NEEDS_FIX |
| 凭据泄漏 | 疑似 token/key（ghp_/sk-/AKIA/glpat-/xoxb-/AIza 等），命中脱敏回显 `[REDACTED_SECRET]` | BLOCKED |
| INFO 级 | 出站代理提及，默认静音，`--show-info` 才显示 | 不阻断 |

规则集中在 `rules/skillhub-spec.json`，调整红线改 JSON 即可。

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

## 三条铁律（写进技能文档时牢记）

1. **功能合法 ≠ 文档合规**：文档绝不出现法律含义明确的敏感词，更不把功能描述成「解决某类访问限制」。
2. **`--proxy` 定位为企业内网统一出网**，明写「不提供也不支持任何规避网络管理措施的能力」。
3. **降级而非绕行**：海外源不可达就降级到国内源 + 离线快照 + 如实标注。

## 贡献

PR 欢迎。技能是给 Agent 的任务说明书，改动建议聚焦一处痛点、附带真实触发样例与预期输出。
规则调整优先改 `rules/skillhub-spec.json`（数据外置），脚本逻辑改动请同步更新 `CHANGELOG.md`。

## 许可证

[MIT-0](LICENSE) — 无需署名，可自由使用、修改、再分发。

## 免责声明

本门禁仅做本地规范预检，不构成 SkillHub 审核保证。最终能否上架由 SkillHub 三线审核
决定，责任由开发者自行承担。
