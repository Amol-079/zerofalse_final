# Zerofalse Python SDK

Runtime security enforcement for AI agents. Zerofalse inspects every tool call before it executes and blocks dangerous ones in real-time.

## Install

```bash
pip install zerofalse
```

## Quickstart

```python
import os
from zerofalse import guard_tool, ZerofalseSecurity

os.environ["ZEROFALSE_API_KEY"] = "zf_live_..."

@guard_tool
def run_command(cmd: str) -> str:
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)

try:
    output = run_command("ls -la")       # ALLOW — executes normally
    run_command("rm -rf /data")          # BLOCK — raises ZerofalseSecurity, never executes
except ZerofalseSecurity as e:
    print(f"Blocked: {e.threat_type}, scan_id={e.scan_id}")
```

## With custom agent ID

```python
@guard_tool(agent_id="crawler-01", on_warn="raise")
def write_file(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)
```

## With explicit client

```python
from zerofalse import ZerofalseClient, guard_tool

client = ZerofalseClient(
    api_key="zf_live_...",
    fail_open=False,   # Block tool calls if API is unreachable
    timeout=3.0,
)

@guard_tool(client=client, agent_id="my-agent")
def query_database(sql: str) -> list:
    ...
```

## LangChain integration

```python
from langchain.tools import Tool
from zerofalse import ZerofalseClient
from zerofalse.integrations.langchain import ZerofalseGuardedTool

zf = ZerofalseClient(api_key="zf_live_...")

my_tool = Tool(name="run_shell", func=lambda x: x, description="Runs shell commands")
guarded = ZerofalseGuardedTool(wrapped_tool=my_tool, zf_client=zf, agent_id="lc-agent-01")

# Use guarded in your LangChain agent instead of my_tool
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ZEROFALSE_API_KEY` | ✅ Yes | Your API key from the dashboard |
| `ZEROFALSE_API_URL` | No | Override API endpoint (default: `https://api.zerofalse.com`) |
| `ZEROFALSE_FAIL_OPEN` | No | Set `false` to block tool calls when API is unreachable |

## Decision behavior

| Decision | What happens |
|---|---|
| `allow` | Tool function executes normally |
| `warn` | Warning is logged, tool function still executes |
| `block` | `ZerofalseSecurity` is raised — tool function **never executes** |

## Using as context manager

```python
with ZerofalseClient(api_key="zf_live_...") as zf:
    result = zf.scan_tool_call(
        tool_name="write_file",
        arguments={"path": "/etc/passwd", "content": "hacked"},
        agent_id="agent-01",
    )
    print(result.decision)   # "block"
    print(result.risk_score) # 0.95
    print(result.evidence)   # ["Sensitive file access"]
```
