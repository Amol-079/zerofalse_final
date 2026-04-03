# Zerofalse v2.0 — AI Agent Security Firewall

Runtime security firewall for AI agents. Inspects every tool call in real-time.

## Quick Start

### 1. Configure Backend
```bash
cp backend/.env.example backend/.env
# Fill in: SUPABASE_URL, SUPABASE_SERVICE_KEY, CLERK_SECRET_KEY, CLERK_WEBHOOK_SECRET
```

### 2. Configure Frontend
```bash
cp frontend/.env.example frontend/.env
# Fill in: REACT_APP_CLERK_PUBLISHABLE_KEY, REACT_APP_API_URL
```

### 3. Run Supabase Schema
Paste `backend/supabase_schema.sql` into Supabase SQL Editor → Run

### 4. Configure Clerk Webhook
- Clerk Dashboard → Webhooks → Add endpoint
- URL: `https://your-backend/api/v1/auth/webhook/clerk`
- Events: `user.created`, `user.updated`, `user.deleted`
- Copy signing secret → `CLERK_WEBHOOK_SECRET` in backend/.env

### 5. Start
```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

## SDK Usage
```bash
pip install ./sdk
```

```python
import os
from zerofalse import guard_tool

os.environ["ZEROFALSE_API_KEY"] = "zf_live_..."

@guard_tool(agent_id="my-agent")
def run_command(command: str) -> str:
    import subprocess
    return subprocess.check_output(command, shell=True, text=True)
```

## Architecture
- **Backend**: FastAPI + Supabase + Clerk + Redis
- **Frontend**: React + Clerk + Tailwind
- **SDK**: Python, sync + async clients
- **Detection**: 4-layer engine (normalization → regex → keyword clusters → semantic)
