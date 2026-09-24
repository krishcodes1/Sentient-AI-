# Crawler AI

[![CI](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml/badge.svg)](https://github.com/krishcodes1/Sentient-AI-/actions/workflows/ci.yml)

**Secure-by-Design Agentic AI Platform**

A self-hosted AI assistant platform (FastAPI + React) with security, user
control, and auditability built into every layer: fine-grained permission
scoping, explicit approval flows for sensitive actions, multi-layer prompt
injection defense, and tamper-evident audit logging. Integrates with Canvas
LMS, Google Workspace, Robinhood Crypto (read-only), and external MCP servers.

**The project lives in [`Sentient-AI-/`](Sentient-AI-/) — see
[`Sentient-AI-/README.md`](Sentient-AI-/README.md) for full setup, and
[`Sentient-AI-/SECURITY.md`](Sentient-AI-/SECURITY.md) for the security
model.**

## Quick start (no commands to type)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) and open it.
2. Download this repository (green **Code** button → **Download ZIP**, or `git clone`).
3. Open the `Sentient-AI-` folder inside it and double-click
   **`Install Crawler AI.command`** (Mac) or **`Install Crawler AI.bat`** (Windows).
   A local page opens in your browser and walks you through four steps:
   check → keys → build → open. macOS may ask you once to allow the file
   (right-click → Open).
4. Crawler AI opens at http://localhost:3000 and its setup wizard takes it
   from there: owner account, AI provider, Telegram, permissions.

Manual and production setups are in [`Sentient-AI-/README.md`](Sentient-AI-/README.md).
Contributors: start with [`Sentient-AI-/docs/team-handoff-2026-09-23.md`](Sentient-AI-/docs/team-handoff-2026-09-23.md)
and pick an item from [`Sentient-AI-/docs/BACKLOG.md`](Sentient-AI-/docs/BACKLOG.md).

For production, use the production compose file instead:

```bash
cd Sentient-AI-/docker
docker compose -f docker-compose.prod.yml up --build -d
```

---

**Author:** Krish Shroff (Team Leader) — CSCI-456 Senior Project, New York
Institute of Technology. **Team:** Rafi Hossain, Miadul Haque, Edrich Silva.
