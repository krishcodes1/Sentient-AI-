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

## Quick start

```bash
git clone https://github.com/krishcodes1/Sentient-AI-.git
cd Sentient-AI-

# Configure environment (add your LLM API key + generated secrets)
cp Sentient-AI-/backend/.env.example Sentient-AI-/backend/.env

# Start everything (dev stack)
cd Sentient-AI-/docker
docker compose up --build
```

Then open http://localhost:3000 (frontend) — API docs at
http://localhost:8000/docs.

For production, use the production compose file instead:

```bash
cd Sentient-AI-/docker
docker compose -f docker-compose.prod.yml up --build -d
```

---

**Author:** Krish Shroff (Team Leader) — CSCI-456 Senior Project, New York
Institute of Technology. **Team:** Rafi Hossain, Miadul Haque, Edrich Silva.
