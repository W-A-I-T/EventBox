# Testing EventBox Server Locally

## Prerequisites
- Deno must be installed: `curl -fsSL https://deno.land/install.sh | sh` (answer Y to PATH prompt, or Ctrl+C after binary installs and manually add `~/.deno/bin` to PATH)
- No Tauri/Rust toolchain needed for server-only testing

## Starting the Server
```bash
export PATH="$HOME/.deno/bin:$PATH"
cd /path/to/EventBox
EVENTBOX_EVENT_ID="<event-id>" EVENTBOX_PORT=8787 deno run \
  --allow-net --allow-read --allow-write --allow-env --allow-ffi --unstable-ffi \
  src-tauri/resources/server.ts
```

The server prints the room code on startup. Note it for auth.

## Getting an Auth Token
```bash
TOKEN=$(curl -s -X POST http://localhost:8787/auth/token \
  -H "Content-Type: application/json" \
  -d '{"room_code":"<ROOM_CODE>","device_id":"test-device","role":"event_admin"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

Roles available: `event_admin`, `scanner`, `judge`, `marshal`, `deck_captain`, `floor_captain`, `scrutineer`, `announcer`, `dj`, `chairman`, `videographer`

## Key Test Flows

### 1. /state/ref Endpoint
- Sync data: `POST /api/sync-ref` with `{"tables":[{"name":"<table>","data":[...]}]}`
- Read data: `GET /state/ref?table=<table>` with Bearer token
- Missing table param returns 400
- Nonexistent table returns `{"data":null}`

### 2. Role-Based Permissions
- Get token with restricted role (e.g., `judge`)
- Judge can submit `score` and `score_submission` ops
- Judge CANNOT submit `checkin`, `marshal`, etc. — expect `{"accepted":false,"reason":"unauthorized"}`
- `videographer` has empty permissions — all ops rejected

### 3. Transaction Atomicity
- Submit a marshal op to set entity to `cancelled`
- Submit same entity with `cancelled` again — FSM rejects
- Check ops table: rejected op should NOT be logged (transaction rolled back)
- Query ops table directly: use `deno eval` with `@db/sqlite@0.12`

### 4. State Endpoints
All require Bearer token:
- `GET /state/checkins` — returns checkins array
- `GET /state/marshal` — returns marshal status array
- `GET /state/heats` — returns heats array
- `GET /state/nowplaying` — returns now_playing object
- `GET /state/ref?table=X` — returns ref data
- Note: `/state/scores` is NOT implemented (returns "unknown state kind")

## Known Gotchas

### queryRows and @db/sqlite@0.12
`stmt.iter()` returns **objects with named columns**, not arrays. The `queryRows()` function must use `Object.values(row)` to convert to arrays, otherwise positional access like `rows[0][0]` returns `undefined`. This was a real bug found during testing (PR #7).

### Deno Installer
The Deno installer may hang at the "Edit shell configs" prompt. If it does, Ctrl+C after the binary downloads and manually add `~/.deno/bin` to PATH.

### SQLite Files
Clean up between test runs: `rm -f eventbox.sqlite eventbox.sqlite-shm eventbox.sqlite-wal`

### Room Code Changes on Restart
Each server restart generates a new room code. Re-read it from stdout.

## CI Sync Between Repos
- `dance-flow-control/public/eventbox/server.ts` syncs to `EventBox/src-tauri/resources/server.ts`
- `dance-flow-control/desktop/src/dashboard.html` syncs to `EventBox/src/index.html`
- `dance-flow-control/desktop/src-tauri/src/main.rs` syncs to `EventBox/src-tauri/src/main.rs`
- Fixes must go into dance-flow-control first or they get overwritten by sync

## Devin Secrets Needed
None required for local server testing. The server generates its own HMAC secret on startup.
