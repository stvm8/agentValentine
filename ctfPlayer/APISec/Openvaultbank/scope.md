# Scope — Openvaultbank

- **Platform:** APISec
- **Target:** https://openvaultbank.com/
- **Objective:** Capture the flags
- **Date:** 2026-04-03

## Known Attack Surface (from agent_learnings)
- `/health` leaks DB creds + JWT hints (unauthenticated)
- PUT /profile mass assignment → `{"role":"admin"}`
- GET/PUT `/accounts/{id}` BOLA — no ownership check, enumerate sequential IDs
- POST `/auth/reset-request` leaks `debug_code` in response body → instant ATO
