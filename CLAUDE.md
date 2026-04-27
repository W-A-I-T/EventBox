# EventBox

LAN Authority Server desktop app for dance competitions. One organizer/judge runs EventBox on their machine; all staff (judges, marshals, scanners) join via room code or QR on any device on the same WiFi. No internet required — fully offline-capable. Cloud sync to dance-flow-control is optional.

**GitHub:** `gh repo view W-A-I-T/EventBox`

## CRITICAL — Source of truth for server.ts

`src-tauri/resources/server.ts` is **owned by [W-A-I-T/dance-flow-control](https://github.com/W-A-I-T/dance-flow-control)**, not this repo.

**Do not edit `server.ts` directly in EventBox.** Changes made here will be overwritten on the next sync.

The flow is:
```
dance-flow-control (source of truth)
  └── .github/workflows/sync-danceflow.yml in EventBox
        pulls server.ts from dance-flow-control on every push to dance-flow-control
        → auto-release-on-sync.yml then cuts a new EventBox release if server.ts changed
```

To change server logic:
1. Edit `server.ts` in [dance-flow-control](https://github.com/W-A-I-T/dance-flow-control) (`src-tauri/resources/server.ts` there maps to here via sync)
2. Push to dance-flow-control
3. CI in EventBox pulls the update automatically within minutes
4. If the file changed, a new EventBox release is built and published automatically

To manually trigger a sync without waiting:
```bash
gh workflow run sync-danceflow.yml --repo W-A-I-T/EventBox
```

## Stack

| Layer | Tech |
|-------|------|
| Desktop shell | Tauri 2.x (Rust) |
| UI | Vanilla JS + HTML/CSS — single file `src/index.html`, no build step |
| Server | Deno 2.1.9 → compiled to `eventbox-server` binary via `deno compile` |
| Database | SQLite (WAL mode) — append-only ops log + materialized state |
| Build | npm + cargo + deno (3-stage: compile server → build Tauri → bundle installers) |

**Default port:** 8787 (env `EVENTBOX_PORT`)

## Key paths

```
src/index.html                    — entire UI (vanilla JS, 19KB, no framework)
src-tauri/
  src/lib.rs                      — Rust app lifecycle: server spawn, orphan cleanup, tray, IPC
  src/main.rs                     — thin entry point calling lib::run()
  resources/server.ts             — Deno server (2635 lines) — THIS IS THE MAIN LOGIC
  resources/eventbox-server       — compiled binary (platform-specific, git-ignored-ish)
  tauri.conf.json                 — Tauri v2 permissions, window config, auto-update URL
  Cargo.toml                      — Rust deps (tauri, tauri-plugin-*, local-ip-address)
.agents/skills/
  testing-eventbox/SKILL.md       — desktop testing guide (WebKitGTK limits, CI flags)
  testing-eventbox-server/SKILL.md — server API testing + known gotchas (integer overflow, etc.)
```

## How to run

```bash
npm install
npm run tauri:dev        # compile server + hot-reload desktop app

# Server only (Deno, no Tauri):
EVENTBOX_EVENT_ID="your-event-uuid" deno run \
  --allow-net --allow-read --allow-write --allow-env --allow-ffi --unstable-ffi \
  src-tauri/resources/server.ts

# Production build:
npm run tauri:build      # produces .msi / .dmg / .deb / .AppImage
```

## Key server endpoints

All require `Authorization: Bearer <token>` except `/auth/token` and `/health`.

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/token` | Issue JWT (room_code + device_id + admin_secret\|staff_session_id) |
| `POST /ops/batch` | Submit ops (checkin, score, marshal, heat, contestant) |
| `GET /state/checkins` `heats` `marshal` `nowplaying` | Read materialized state |
| `POST /api/staff-sessions` | Create staff session |
| `POST /api/staff-sessions/join` | Join with room code |
| `POST /api/sync-ref` | Receive reference data from cloud |
| `WS /ws?token=...` | Real-time broadcast (all clients receive accepted ops) |

## Auth model

- Room code (6-digit, persisted in SQLite) → staff scan/enter to join
- JWT (HMAC-SHA256, 12hr TTL) → all requests after join
- Roles: `event_admin`, `judge`, `marshal`, `scanner`, `floor_captain`, `viewer`

## Development commands

```bash
npm run compile-server          # compile Deno server for current platform
npm run compile-server:windows  # cross-compile x86_64-pc-windows-msvc
npm run compile-server:mac-arm  # aarch64-apple-darwin
npm run compile-server:linux    # x86_64-unknown-linux-gnu

npm test
cargo test --manifest-path src-tauri/Cargo.toml
```

## Release

```bash
git tag v0.x.y && git push origin v0.x.y
# GitHub Actions builds all platforms and creates release automatically
```

## Known gotchas

- **WebKitGTK:** can't click buttons via xdotool in CI — use `--event-id` CLI flag instead
- **`@db/sqlite@0.12` bug:** 32-bit integer overflow on millisecond timestamps in `staff_sessions.expires_at` — use `/api/staff-sessions/join` auth path, not `staff_session_id`
- **Compiled binary validation:** Rust checks for `"d3n0l4nd"` magic bytes before using the binary; falls back to system Deno + server.ts if corrupt
- **`src-tauri/target/`** is large — never read recursively

## Architecture notes

- Server is the main logic — Rust only handles app lifecycle, process spawning, and orphan cleanup
- Orphan cleanup: on startup checks `/tmp/eventbox-server.pid`, kills leftover process via `/proc/<pid>/cmdline` (Linux) / `ps` (macOS) / `tasklist` (Windows)
- Cloud sync: ops are marked `synced_at` to push to dance-flow-control (Supabase). Sync failure does not affect offline operation.
- `server.ts` is synced FROM dance-flow-control (source of truth) via `.github/workflows/sync-danceflow.yml` — never edit it here directly
