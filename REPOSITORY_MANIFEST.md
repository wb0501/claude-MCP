# REPOSITORY_MANIFEST — claude-MCP

本地 Claude Code + 模型中转站执行 MCPMark 工作负载的源码。

- Repository: `claude-MCP`
- Local path: `/home/claude-MCP/mcpmark`（工作目录） / `/home/claude-MCP/claude-MCP`（独立 Git 副本）
- 上游：`eval-sys/mcpmark` @ `cd45b7f`
- Python: >= 3.11（本机 3.14）

## 纳入版本管理的文件

| 路径 | 用途 |
|---|---|
| `run_mcpmark_*_claude.py` | 6 个 MCP 服务的 Claude 本地 runner |
| `mcp_remote_support.py` | 远程 MCP / 模型中转辅助 |
| `pipeline.py` | MCPMark 评估流水线 |
| `run-task.sh` / `run-benchmark.sh` | 单任务与批量执行 |
| `rerun_failed_github_tasks.sh` | 失败任务重跑 |
| `analyze_*.py`, `plot.py` | 流量与结果分析 |
| `src/` | MCPMark 核心库（90 个文件） |
| `tasks/` | MCPMark Verified 任务定义（JSON/Markdown/Python/SQL/TXT） |
| `docs/` | 上游文档 |
| `pyproject.toml`, `pixi.lock` | Python 依赖锁定 |
| `Dockerfile`, `build-docker.sh` | 容器构建 |
| `.github/` | CI 配置 |
| `.mcp_env.example` | 环境变量模板（无值） |
| `README.md`, `REPOSITORY_MANIFEST.md`, `.gitignore` | 仓库文档与排除规则 |

## 明确排除

```text
.mcp_env                 真实 Notion/GitHub/Postgres 凭据
.aws/, .codex/           个人认证目录
results_claude_mcpmark_*/ 所有实验结果
github_state/, postgres_state/  运行状态
.mcpmark-bin/, .mcpmark_backups/, .playwright-mcp/  二进制与缓存
test_environments/       环境 fixture（67 MB）
*.zip, *.pcapng, *.jsonl, *.log  实验数据
.venv/, __pycache__/, *.pyc, *.pkl  环境与缓存
```

## 已知扫描误报

`tasks/github/standard/mcpmark-cicd/pr_automation_workflow/verify.py` 中包含
**故意伪造**的密码/API key 模式，用于测试 secret detection；该文件已从本仓库
剔除，以保持 secret scan 干净。上游任务集因此缺少该单个 task 文件。

## 与其它仓库的关系

本仓库是独立的 MCPMark 工作负载执行代码，不与 `codex_qwen` /
`codex_qwen_GAIA` / `waitung-inference-server-measurement` 共享运行时；
它通过 MCP 服务与模型中转站运行，可用于跨 Benchmark 的 Agent 流量对照。
