# claude-MCP

本地 Claude Code + 模型中转站驱动的 **MCPMark** 工作负载执行与流量分析代码。

本仓库是 `/home/claude-MCP/mcpmark` 工作目录中与本次实验直接相关的运行
脚本、任务定义和依赖的独立版本管理副本。它不是 MCPMark 上游仓库，也不包含
实验数据、凭据或运行状态。

## 与上游的关系

- 上游项目：`eval-sys/mcpmark`
- 基线 commit：`cd45b7f`（MCPMark Verified）
- 本仓库保留上游 `src/`、`tasks/`、`docs/` 与依赖锁定文件，使运行脚本可直接执行
- 本仓库新增/维护的是 Claude 本地执行脚本、模型中转配置、流量分析脚本

## 关键运行脚本

| 文件 | 用途 |
|---|---|
| `run_mcpmark_filesystem_claude.py` | Filesystem MCP 工作负载，Claude CLI 驱动 |
| `run_mcpmark_github_claude.py` | GitHub MCP 工作负载 |
| `run_mcpmark_notion_claude.py` | Notion MCP 工作负载 |
| `run_mcpmark_playwright_claude.py` | Playwright MCP 工作负载 |
| `run_mcpmark_playwright_webarena_claude.py` | Playwright WebArena 变体 |
| `run_mcpmark_postgres_claude.py` | Postgres MCP 工作负载 |
| `mcp_remote_support.py` | 远程 MCP / 模型中转辅助 |
| `pipeline.py` | MCPMark 评估流水线入口 |
| `run-task.sh` / `run-benchmark.sh` | 单任务与批量执行 |
| `rerun_failed_github_tasks.sh` | 失败 GitHub 任务重跑 |
| `analyze_bytes.py`, `analyze_delay.py`, `analyze_sse.py`, `analyze_tool.py`, `analyze_traffic.py` | PCAP/SSE/工具调用流量分析 |
| `plot.py` | 结果绘图 |

## 环境

- Python >= 3.11（本机基线 3.14）
- Claude Code CLI（通过模型中转站，使用 `ANTHROPIC_*` 环境变量）
- MCP 服务：Filesystem / GitHub / Notion / Postgres / Playwright
- 依赖：`pyproject.toml` + `pixi.lock`；`src/` 与 `tasks/` 已随仓库提供

## 配置

```bash
cp .mcp_env.example .mcp_env
# 填入本地凭据；.mcp_env 已被 .gitignore 排除
```

## 快速开始

```bash
python -m pip install -e .        # 或使用 pixi
./run-task.sh --help
./run-benchmark.sh --help
python run_mcpmark_filesystem_claude.py --help
```

## 数据策略

`.mcp_env`、`results*/`、`github_state/`、`postgres_state/`、`.mcpmark-bin/`、
`.playwright-mcp/`、`test_environments/`、PCAP/JSONL 日志和所有实验 ZIP 均不入库。
