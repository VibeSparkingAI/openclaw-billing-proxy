# Changelog

## v1.1.0 — 2026-04-05

### Simplified to verified minimal detection bypasses

**Changes:**
- Removed Claude Code tool stub injection — systematic testing proved tool fingerprinting is NOT part of Anthropic's detection
- Reduced sanitization from 18 patterns to 7 verified triggers
- Updated README with accurate detection documentation
- Updated config.example.json with minimal replacement set

**Verified triggers (the only terms Anthropic detects):**
1. `OpenClaw` (case-insensitive) — the platform name
2. `openclaw` — lowercase variant
3. `sessions_spawn` — OpenClaw session management tool
4. `sessions_list` — OpenClaw session management tool
5. `sessions_history` — OpenClaw session management tool
6. `sessions_send` — OpenClaw session management tool
7. `running inside` — the self-declaration phrase ("running inside OpenClaw")

**Confirmed safe (NOT detected):**
- Assistant names (e.g., "custom assistant name")
- Workspace files (AGENTS.md, SOUL.md, USER.md)
- Config paths (.openclaw/, openclaw.json)
- Plugin names (lossless-claw)
- Individual tool names (exec, lcm_grep, gateway, cron, etc.)
- Bot names (custom assistant nameAssistantBot)
- Runtime references (pi-embedded, pi-ai)

**Testing:** Validated with 478+ real OpenClaw requests on production instance.

---

## v1.0.0 — 2026-04-05

### Initial release

- Billing header injection (84-char Claude Code identifier in system prompt)
- OAuth token swap (Claude Code credentials from ~/.claude/.credentials.json)
- Beta flag injection (oauth-2025-04-20, claude-code-20250219, etc.)
- 18 sanitization patterns (overly broad — reduced in v1.1.0)
- Claude Code tool stub injection (unnecessary — removed in v1.1.0)
- Auto-detect credentials path (cross-platform)
- Health endpoint (/health)
- Configurable via config.json or CLI args
- Zero dependencies
