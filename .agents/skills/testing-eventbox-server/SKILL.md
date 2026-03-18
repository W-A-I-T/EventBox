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

The `/auth/token` endpoint derives roles server-side. **Never pass `role` directly** — it will be ignored.

### Admin Token (via admin_secret)
```bash
# admin_secret defaults to ROOM_CODE unless EVENTBOX_ADMIN_SECRET is set
TOKEN=$(curl -s -X POST http://localhost:8787/auth/token \
  -H "Content-Type: application/json" \
  -d '{"room_code":"<ROOM_CODE>","device_id":"admin-dev","admin_secret":"<ROOM_CODE>"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

### Staff Token (via staff_session_id)
```bash
# First create a staff session as admin, then use the session ID
TOKEN=$(curl -s -X POST http://localhost:8787/auth/token \
  -H "Content-Type: application/json" \
  -d '{"room_code":"<ROOM_CODE>","device_id":"staff-dev","staff_session_id":"<SESSION_ID>"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

### Viewer Token (no credentials)
```bash
# Omitting admin_secret and staff_session_id gives "viewer" role (read-only)
TOKEN=$(curl -s -X POST http://localhost:8787/auth/token \
  -H "Content-Type: application/json" \
  -d '{"room_code":"<ROOM_CODE>","device_id":"viewer-dev"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
```

### Shortcut: Universal Room Code Join (bypasses staff_session_id auth path)
```bash
# This creates a staff session AND issues a token in one call
# Useful for testing because it avoids the integer overflow bug in staff_session_id auth
curl -s -X POST http://localhost:8787/api/staff-sessions/join \
  -H "Content-Type: application/json" \
  -d '{"join_code":"<ROOM_CODE>","device_id":"judge-dev","staff_name":"Test Judge","role":"judge"}'
```

Roles available: `event_admin`, `scanner`, `judge`, `marshal`, `deck_captain`, `floor_captain`, `scrutineer`, `announcer`, `dj`, `chairman`, `videographer`

## Creating Staff Sessions
```bash
# Note: field is "staff_name" not "name"
curl -s -X POST http://localhost:8787/api/staff-sessions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"staff_name":"Test Judge","role":"judge"}'
```

## Key Test Flows

### 1. /state/ref Endpoint
- Sync data: `POST /api/sync-ref` with `{"tables":[{"name":"<table>","data":[...]}]}`
- Read data: `GET /state/ref?table=<table>` with Bearer token
- Missing table param returns 400
- Nonexistent table returns `{"data":null}`

### 2. Role-Based Permissions
- Get token with restricted role (e.g., `judge`) using universal room code join
- Judge can submit `score` and `score_submission` ops
- Judge CANNOT submit `checkin`, `marshal`, etc. — expect `{"accepted":false,"reason":"unauthorized"}`
- `videographer` has empty permissions — all ops rejected

### 3. Transaction Atomicity
- Submit a marshal op to set entity to `cancelled`
- Submit same entity with `cancelled` again — FSM rejects
- Check ops table: rejected op should NOT be logged (transaction rolled back)
- Query ops table directly: use `deno eval` with `@db/sqlite@0.12`

### 4. XSS Prevention
- Navigate to `/app/marshal?eventId=<script>alert('xss')</script>` — should NOT execute JS
- Check page source: eventId should be URL-encoded in href attributes
- All HTML template interpolations should use `escapeHtml()`, JS contexts use `JSON.stringify()`, URL params use `encodeURIComponent()`

### 5. State Endpoints
All require Bearer token:
- `GET /state/checkins` — returns checkins array
- `GET /state/marshal` — returns marshal status array
- `GET /state/heats` — returns heats array
- `GET /state/nowplaying` — returns now_playing object
- `GET /state/ref?table=X` — returns ref data
- Note: `/state/scores` is NOT implemented (returns "unknown state kind")

## Known Gotchas

### @db/sqlite@0.12 Integer Overflow (CRITICAL)
Millisecond timestamps like `Date.now()` (e.g. `1772728436430`) exceed the 32-bit signed integer range (`2^31 - 1 = 2147483647`). The `@db/sqlite@0.12` JS binding returns these as negative numbers (e.g. `-1093056818`). This affects:
- `staff_sessions.expires_at` — causes `/auth/token` with `staff_session_id` to always return `session_expired`
- `updated_at_ms` in state queries — shows wrong timestamps
- **Workaround**: Use the universal room code join path (`/api/staff-sessions/join`) which issues tokens directly without reading `expires_at` back from the DB
- **Fix needed**: Store timestamps as TEXT, or use `CAST(column AS TEXT)` when reading, or switch to seconds instead of milliseconds

### queryRows and @db/sqlite@0.12
`stmt.iter()` returns **objects with named columns**, not arrays. The `queryRows()` function must use `Object.values(row)` to convert to arrays, otherwise positional access like `rows[0][0]` returns `undefined`. This was a real bug found during testing (PR #7).

### Auth Flow Changed — No More Client-Supplied Roles
The `/auth/token` endpoint no longer accepts `role` in the request body. You must provide:
- `admin_secret` (defaults to ROOM_CODE) for `event_admin` role
- `staff_session_id` for staff roles (looked up from DB)
- Neither → gets `viewer` role (read-only)

### Staff Session Field Name
The `POST /api/staff-sessions` endpoint expects `staff_name` (not `name`). Getting this wrong returns `{"error":"role and staff_name required"}`.

### Deno Installer
The Deno installer may hang at the "Edit shell configs" prompt. If it does, Ctrl+C after the binary downloads and manually add `~/.deno/bin` to PATH.

### Templates Not Found in Compiled Binary
`deno compile` does NOT bundle files read via `Deno.readTextFile()`. If the server
crashes immediately with "No such file or directory" for template files, the
templates need to be embedded as string literals in `server.ts`. In development
mode (`deno run`), templates load from the filesystem. In production (compiled
binary), embedded fallbacks are used.

### SQLite Files
Clean up between test runs: `rm -f eventbox.sqlite eventbox.sqlite-shm eventbox.sqlite-wal`

### Room Code Changes on Restart
Each server restart generates a new room code. Re-read it from stdout.

## CI Sync Between Repos
- `dance-flow-control/public/eventbox/server.ts` syncs to `EventBox/src-tauri/resources/server.ts`
- **Only `server.ts` is synced.** `lib.rs`, `Cargo.toml`, `tauri.conf.json`, `index.html`, and `README.md` are NOT synced because EventBox has been migrated to Tauri v2 while dance-flow-control remains on Tauri v1.
- Sync triggers: daily at 06:00 UTC, manual dispatch, or `repository_dispatch` from dance-flow-control on push to main
- dance-flow-control has a workflow (`trigger-eventbox-sync.yml`) that auto-dispatches on push to synced files — requires `EVENTBOX_SYNC_TOKEN` secret (GitHub PAT with repo scope)
- Fixes to `server.ts` must go into dance-flow-control first or they get overwritten by sync
- Fixes to `lib.rs`, `Cargo.toml`, or other EventBox-only files go directly into EventBox

## Devin Secrets Needed
None required for local server testing. The server generates its own HMAC secret on startup.
