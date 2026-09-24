# Investor presentation — 2026-09-25

**Everything shown runs live on a real account.**

## Live walkthrough (8–10 minutes)
1. **Install** — double-click installer → keys → setup wizard (the AI key is tested before it saves; Permissions honestly says "See my screen" isn't available in a container).
2. **Canvas from Telegram** — "What's due this week, and am I missing anything?" → answers from real NYIT Canvas.
3. **Flights from Telegram** — "Cheapest flight NYC → LA next Friday, send me a screenshot" → progress messages, screenshot, fare, and the cost line **≈ $0.002** (OpenClaw: ~$10 for the same task).
4. **Approvals** — "Submit my assignment for X" → Approve/Deny card on the phone → tap **Deny** live → show the Audit log row.
5. **Security** — a prompt-injection attempt is blocked and logged; turn "Browse the web" off in Permissions and ask again → the agent explains it's off.
6. **Roadmap slide** — browser control (Canvas without the API), computer control, the signed desktop app, native install.

## Tonight's assignments (≈3 h each, no file overlap)

| Who | Build | Files | Done when |
|---|---|---|---|
| **Rafi** | Telegram safety: only the linked account can talk to the bot (backlog A1); `/stop` cancels a running task (A2); link previews off | `backend/services/notifications/telegram.py` | a second Telegram account is ignored; `/stop` ends a long task |
| **Miadul** | Cost line on every Telegram reply (B1) — "5.3k tokens · ≈$0.002"; price the Gemini model ids used in the presentation (B3) | `backend/api/routes/agent.py` (`build_chat_applier`), `backend/services/usage/pricing.py` | every Telegram reply ends with a cost line |
| **Edrich** | Screenshots show as images in web chat, not JSON (E2); hide "Create one" on login when registration is closed (E3) | `frontend/src/pages/Chat.tsx` (~line 139), `frontend/src/pages/Login.tsx` | the flight screenshot renders as an image on the web |
| **Krish** | Real Canvas: Canvas → Account → Settings → **New Access Token** → Connectors → Canvas; rehearse flows 2–4 on Telegram; write the talk track | Connectors page | "what's due this week" answers correctly 3 times in a row |
| **Claude** | Progress messages on Telegram ("Searching…", "Taking a screenshot…") (A6); review/merge PRs; full rehearsal sweep and fixes; browser control, computer control and the desktop app | runtime → Telegram; new capabilities | all 5 flows pass twice |

**Rules:** branch from `main` (`git checkout -b feat/<id>-<name>`), one pull request per item, CI green before merge, commit messages reviewed by Krish. **Code freeze 11 pm** — bug fixes only after that, then rehearsal.

## So nothing breaks on stage
- **AI key:** the free Gemini tier rate-limits after a few quick turns. Turn on billing for the key (cents), or add a second provider in Settings ▸ Server as a backup.
- **One presenting Mac runs the Telegram bot.** Everyone else makes their **own** bot in @BotFather — two computers on one token steal each other's messages.
- **Day of:** Mac awake and plugged in, Docker Desktop open before starting, notifications off, phone hotspot as backup Wi-Fi.
- **Backup:** screen-record each flow after tonight's rehearsal; play the recording if the network fails.

**Shown live only if they pass a full rehearsal tonight:** browser control and computer control (60-second segment each). Otherwise they stay on the roadmap slide.
