/**
 * EventBox v0 — LAN Authority Server
 *
 * A single Deno binary that serves as the local source of truth for one event.
 * Staff devices connect via WebSocket on the LAN; all writes go through an
 * append-only op log with idempotent deduplication.
 *
 * Usage:
 *   deno run --allow-net --allow-read --allow-write --allow-env --allow-ffi --unstable-ffi server.ts
 *   deno compile --allow-net --allow-read --allow-write --allow-env --allow-ffi --unstable-ffi --output eventbox server.ts
 *   ./eventbox --event-id <uuid> --port 8787
 *
 * Environment variables:
 *   EVENTBOX_PORT       (default 8787)
 *   EVENTBOX_DB         (default ./eventbox.sqlite)
 *   EVENTBOX_ROOM_CODE  (6-digit code; auto-generated if omitted)
 *   EVENTBOX_EVENT_ID   (required; the event this instance serves)
 *   EVENTBOX_SECRET     (HMAC signing key; auto-generated if omitted)
 */

import { Database } from "jsr:@db/sqlite@0.12";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = Number(Deno.env.get("EVENTBOX_PORT") ?? 8787);
const DB_PATH = Deno.env.get("EVENTBOX_DB") ?? "./eventbox.sqlite";
// Room code: env override > SQLite persisted > random
const _ROOM_CODE_ENV = Deno.env.get("EVENTBOX_ROOM_CODE");
let ROOM_CODE = _ROOM_CODE_ENV ?? String(Math.floor(100000 + Math.random() * 900000));
const ADMIN_SECRET =
  Deno.env.get("EVENTBOX_ADMIN_SECRET") ??
  ROOM_CODE;
const EVENT_ID = Deno.env.get("EVENTBOX_EVENT_ID") ?? "";
const SECRET =
  Deno.env.get("EVENTBOX_SECRET") ??
  crypto.randomUUID().replace(/-/g, "");

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
let SERVER_START = Date.now(); // Updated after Deno.serve() binds

// Module-level cached event name (updated on sync)
let cachedEventName = "";
function refreshCachedEventName() {
  try {
    const rows = queryRows(`SELECT data_json FROM ref_data WHERE event_id=? AND table_name='event'`, [EVENT_ID]);
    if (rows.length > 0) {
      const parsed = JSON.parse(String(rows[0][0]));
      if (Array.isArray(parsed) && parsed[0]?.name) cachedEventName = parsed[0].name;
      else if (parsed?.name) cachedEventName = parsed.name;
    }
  } catch {}
}

if (!EVENT_ID) {
  console.error("ERROR: EVENTBOX_EVENT_ID is required. Pass it via env or --event-id flag.");
  Deno.exit(1);
}

const db = new Database(DB_PATH);

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------
db.exec(`
PRAGMA journal_mode=WAL;

-- Append-only operation log (the single source of truth)
CREATE TABLE IF NOT EXISTS ops (
  op_id          TEXT PRIMARY KEY,
  event_id       TEXT NOT NULL,
  actor_device_id TEXT,
  actor_role     TEXT,
  op_type        TEXT NOT NULL,
  entity_type    TEXT,
  entity_id      TEXT,
  payload_json   TEXT NOT NULL,
  created_at_ms  INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL,
  synced_at      TEXT             -- NULL until pushed to cloud
);

CREATE INDEX IF NOT EXISTS idx_ops_event_time ON ops(event_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_ops_unsynced ON ops(synced_at) WHERE synced_at IS NULL;

-- ======================== Materialized state tables ========================

CREATE TABLE IF NOT EXISTS checkins (
  event_id       TEXT NOT NULL,
  credential_id  TEXT NOT NULL,
  status         TEXT NOT NULL,
  device_id      TEXT,
  updated_at_ms  INTEGER NOT NULL,
  PRIMARY KEY(event_id, credential_id)
);

CREATE TABLE IF NOT EXISTS marshal_status (
  event_id       TEXT NOT NULL,
  heat_entry_id  TEXT NOT NULL,
  status         TEXT NOT NULL,
  updated_by     TEXT,
  updated_at_ms  INTEGER NOT NULL,
  PRIMARY KEY(event_id, heat_entry_id)
);

CREATE TABLE IF NOT EXISTS heat_status (
  event_id       TEXT NOT NULL,
  heat_id        TEXT NOT NULL,
  status         TEXT NOT NULL,
  updated_by     TEXT,
  updated_at_ms  INTEGER NOT NULL,
  PRIMARY KEY(event_id, heat_id)
);

CREATE TABLE IF NOT EXISTS judge_marks (
  event_id           TEXT NOT NULL,
  heat_id            TEXT NOT NULL,
  dance_code         TEXT NOT NULL,
  judge_assignment_id TEXT NOT NULL,
  heat_entry_id      TEXT NOT NULL,
  mark_type          TEXT NOT NULL,
  mark_value         TEXT NOT NULL,
  updated_at_ms      INTEGER NOT NULL,
  PRIMARY KEY(event_id, heat_id, dance_code, judge_assignment_id, heat_entry_id)
);

CREATE TABLE IF NOT EXISTS judge_submissions (
  event_id           TEXT NOT NULL,
  heat_id            TEXT NOT NULL,
  dance_code         TEXT NOT NULL,
  judge_assignment_id TEXT NOT NULL,
  submitted_at_ms    INTEGER NOT NULL,
  PRIMARY KEY(event_id, heat_id, dance_code, judge_assignment_id)
);

CREATE TABLE IF NOT EXISTS scratches (
  event_id       TEXT NOT NULL,
  heat_entry_id  TEXT NOT NULL,
  reason         TEXT,
  requested_by   TEXT,
  requested_at   TEXT,
  PRIMARY KEY(event_id, heat_entry_id)
);

CREATE TABLE IF NOT EXISTS now_playing (
  event_id       TEXT PRIMARY KEY,
  heat_id        TEXT,
  heat_number    INTEGER,
  division_name  TEXT,
  dance_code     TEXT,
  status         TEXT,
  updated_at_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS published_results (
  event_id       TEXT NOT NULL,
  heat_id        TEXT NOT NULL,
  result_json    TEXT NOT NULL,
  published_by   TEXT,
  published_at_ms INTEGER NOT NULL,
  PRIMARY KEY(event_id, heat_id)
);

CREATE TABLE IF NOT EXISTS ref_data (
  event_id       TEXT NOT NULL,
  table_name     TEXT NOT NULL,
  data_json      TEXT NOT NULL,
  fetched_at     TEXT NOT NULL,
  PRIMARY KEY(event_id, table_name)
);

-- Staff sessions for BYOD portal
CREATE TABLE IF NOT EXISTS staff_sessions (
  id             TEXT PRIMARY KEY,
  event_id       TEXT NOT NULL,
  role           TEXT NOT NULL,
  staff_name     TEXT NOT NULL,
  join_code      TEXT NOT NULL UNIQUE,
  device_id      TEXT,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER
);

-- Server config persistence (room code, etc.)
CREATE TABLE IF NOT EXISTS server_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

// Persist / restore room code
if (!_ROOM_CODE_ENV) {
  try {
    const rows = queryRows(`SELECT value FROM server_config WHERE key='room_code'`, []);
    if (rows.length > 0) {
      ROOM_CODE = String(rows[0][0]);
    } else {
      queryRun(`INSERT INTO server_config(key, value) VALUES('room_code', ?)`, [ROOM_CODE]);
    }
  } catch { /* first run — table just created, write below */ }
}

// Initialize cached event name from existing ref_data
refreshCachedEventName();
// ---------------------------------------------------------------------------
// Helper: run a query that returns rows as arrays of values
// ---------------------------------------------------------------------------
function queryRows(sql: string, params: unknown[] = []): unknown[][] {
  const stmt = db.prepare(sql);
  const rows: unknown[][] = [];
  for (const row of stmt.iter(...params)) {
    rows.push(Object.values(row as Record<string, unknown>));
  }
  return rows;
}

function queryRun(sql: string, params: unknown[] = []): void {
  db.prepare(sql).run(...params);
}

// ---------------------------------------------------------------------------
// HMAC Token auth
// ---------------------------------------------------------------------------
interface TokenClaims {
  event_id: string;
  device_id: string;
  role?: string;
  staff_session_id?: string;
  exp: number;
}

const encoder = new TextEncoder();

function toBase64Url(str: string): string {
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(str: string): string {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return s;
}

async function hmacSign(payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return toBase64Url(btoa(String.fromCharCode(...new Uint8Array(sig))));
}

async function hmacVerify(payload: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(payload);
  return expected === signature;
}

async function issueToken(deviceId: string, role?: string, staffSessionId?: string): Promise<string> {
  const claims: TokenClaims = {
    event_id: EVENT_ID,
    device_id: deviceId,
    role,
    staff_session_id: staffSessionId,
    exp: Date.now() + TOKEN_TTL_MS,
  };
  const payload = toBase64Url(btoa(JSON.stringify(claims)));
  const sig = await hmacSign(payload);
  return `${payload}.${sig}`;
}

async function verifyToken(token: string): Promise<TokenClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const valid = await hmacVerify(payload, sig);
  if (!valid) return null;
  try {
    const claims = JSON.parse(atob(fromBase64Url(payload))) as TokenClaims;
    if (claims.exp < Date.now()) return null;
    if (claims.event_id !== EVENT_ID) return null;
    return claims;
  } catch {
    return null;
  }
}

async function authenticate(req: Request): Promise<TokenClaims | null> {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return verifyToken(auth.slice(7));
}

// ---------------------------------------------------------------------------
// Role-based op permissions (Fix #1: server-side authorization)
// ---------------------------------------------------------------------------
const ROLE_OP_PERMISSIONS: Record<string, string[]> = {
  scanner: ["checkin"],
  judge: ["score", "score_submission"],
  marshal: ["marshal", "scratch", "heat_state"],
  deck_captain: ["marshal", "heat_state"],
  floor_captain: ["marshal", "heat_state", "scratch"],
  scrutineer: ["result_publish"],
  announcer: ["nowplaying"],
  dj: ["nowplaying"],
  chairman: ["chairman_override", "heat_state", "marshal", "scratch", "nowplaying"],
  videographer: [],
  event_admin: [
    "checkin", "score", "score_submission", "marshal", "heat_state",
    "scratch", "nowplaying", "result_publish", "chairman_override",
  ],
};

function isRoleAllowed(role: string | undefined, opType: string): boolean {
  if (!role) return false;
  const allowed = ROLE_OP_PERMISSIONS[role];
  if (!allowed) return false;
  return allowed.includes(opType);
}

// ---------------------------------------------------------------------------
// FSM guard
// ---------------------------------------------------------------------------
const STATE_RANK: Record<string, number> = {
  scheduled: 0,
  in_hole: 1,
  on_deck: 2,
  on_floor: 3,
  completed: 4,
  cancelled: 99,
};

function isFsmAllowed(currentState: string | null, newState: string): boolean {
  if (!currentState) return true;
  // Fix #5: guard cancelled → cancelled no-op
  if (currentState === newState) return false;
  if (newState === "cancelled") return true;
  const currentRank = STATE_RANK[currentState] ?? 0;
  const newRank = STATE_RANK[newState] ?? 0;
  return newRank >= currentRank;
}

// ---------------------------------------------------------------------------
// Op types
// ---------------------------------------------------------------------------
type Op = {
  op_id: string;
  event_id: string;
  actor_device_id?: string;
  actor_role?: string;
  op_type: string;
  entity_type?: string;
  entity_id?: string;
  payload: unknown;
  created_at_ms: number;
};

type ApplyResult =
  | { accepted: true }
  | { accepted: false; reason: "duplicate" | "fsm_rejected" | "invalid" | "wrong_event" | "unauthorized" };

// ---------------------------------------------------------------------------
// WebSocket management
// ---------------------------------------------------------------------------
const wsClientsByEvent = new Map<string, Set<WebSocket>>();

function broadcastToEvent(eventId: string, message: unknown, exclude?: WebSocket): void {
  const set = wsClientsByEvent.get(eventId);
  if (!set) return;
  const raw = JSON.stringify(message);
  for (const ws of set) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      try { ws.send(raw); } catch { /* client gone */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Reducers — apply op to materialized state
// ---------------------------------------------------------------------------
function applyOp(op: Op): ApplyResult {
  if (op.event_id !== EVENT_ID) {
    return { accepted: false, reason: "wrong_event" };
  }

  // Fix #1: Server-side role authorization
  if (!isRoleAllowed(op.actor_role, op.op_type)) {
    return { accepted: false, reason: "unauthorized" };
  }

  const now = Date.now();

  // Wrap in transaction for data integrity
  db.exec("BEGIN");
  try {

  // 1. Idempotent insert into op log
  try {
    queryRun(
      `INSERT INTO ops(op_id,event_id,actor_device_id,actor_role,op_type,entity_type,entity_id,payload_json,created_at_ms,received_at_ms)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        op.op_id, op.event_id, op.actor_device_id ?? null,
        op.actor_role ?? null, op.op_type, op.entity_type ?? null,
        op.entity_id ?? null, JSON.stringify(op.payload ?? {}),
        op.created_at_ms, now,
      ],
    );
  } catch {
    db.exec("ROLLBACK");
    return { accepted: false, reason: "duplicate" };
  }

  // 2. Reduce into materialized state
  const p = op.payload as Record<string, unknown>;

  switch (op.op_type) {
    case "checkin": {
      if (p?.credential_id && p?.status) {
        queryRun(
          `INSERT INTO checkins(event_id,credential_id,status,device_id,updated_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,credential_id) DO UPDATE SET
             status=excluded.status, device_id=excluded.device_id, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.credential_id, p.status, op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    case "marshal": {
      if (p?.heat_entry_id && p?.status) {
        const rows = queryRows(
          `SELECT status FROM marshal_status WHERE event_id=? AND heat_entry_id=?`,
          [op.event_id, p.heat_entry_id],
        );
        const currentState = rows.length > 0 ? String(rows[0][0]) : null;

        if (!isFsmAllowed(currentState, p.status as string)) {
          db.exec("ROLLBACK");
          return { accepted: false, reason: "fsm_rejected" };
        }

        queryRun(
          `INSERT INTO marshal_status(event_id,heat_entry_id,status,updated_by,updated_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_entry_id) DO UPDATE SET
             status=excluded.status, updated_by=excluded.updated_by, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.heat_entry_id, p.status, op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    case "heat_state": {
      if (p?.heat_id && p?.status) {
        const rows = queryRows(
          `SELECT status FROM heat_status WHERE event_id=? AND heat_id=?`,
          [op.event_id, p.heat_id],
        );
        const currentState = rows.length > 0 ? String(rows[0][0]) : null;

        if (!isFsmAllowed(currentState, p.status as string)) {
          db.exec("ROLLBACK");
          return { accepted: false, reason: "fsm_rejected" };
        }

        queryRun(
          `INSERT INTO heat_status(event_id,heat_id,status,updated_by,updated_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_id) DO UPDATE SET
             status=excluded.status, updated_by=excluded.updated_by, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.heat_id, p.status, op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    case "score": {
      if (p?.heat_id && p?.dance_code && p?.judge_assignment_id && p?.heat_entry_id) {
        queryRun(
          `INSERT INTO judge_marks(event_id,heat_id,dance_code,judge_assignment_id,heat_entry_id,mark_type,mark_value,updated_at_ms)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(event_id,heat_id,dance_code,judge_assignment_id,heat_entry_id) DO UPDATE SET
             mark_type=excluded.mark_type, mark_value=excluded.mark_value, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.heat_id, p.dance_code, p.judge_assignment_id, p.heat_entry_id, p.mark_type ?? "ordinal", JSON.stringify(p.mark_value), now],
        );
      }
      break;
    }

    case "score_submission": {
      if (p?.heat_id && p?.dance_code && p?.judge_assignment_id) {
        queryRun(
          `INSERT INTO judge_submissions(event_id,heat_id,dance_code,judge_assignment_id,submitted_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_id,dance_code,judge_assignment_id) DO UPDATE SET
             submitted_at_ms=excluded.submitted_at_ms`,
          [op.event_id, p.heat_id, p.dance_code, p.judge_assignment_id, now],
        );
      }
      break;
    }

    case "scratch": {
      if (p?.heat_entry_id) {
        queryRun(
          `INSERT INTO scratches(event_id,heat_entry_id,reason,requested_by,requested_at)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_entry_id) DO UPDATE SET
             reason=excluded.reason, requested_by=excluded.requested_by, requested_at=excluded.requested_at`,
          [op.event_id, p.heat_entry_id, p.reason ?? null, p.requested_by ?? null, p.requested_at ?? new Date(now).toISOString()],
        );

        queryRun(
          `INSERT INTO marshal_status(event_id,heat_entry_id,status,updated_by,updated_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_entry_id) DO UPDATE SET
             status='cancelled', updated_by=excluded.updated_by, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.heat_entry_id, "cancelled", op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    case "nowplaying": {
      queryRun(
        `INSERT INTO now_playing(event_id,heat_id,heat_number,division_name,dance_code,status,updated_at_ms)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(event_id) DO UPDATE SET
           heat_id=excluded.heat_id, heat_number=excluded.heat_number,
           division_name=excluded.division_name, dance_code=excluded.dance_code,
           status=excluded.status, updated_at_ms=excluded.updated_at_ms`,
        [op.event_id, p.heat_id ?? null, p.heat_number ?? null, p.division_name ?? null, p.dance_code ?? null, p.status ?? "playing", now],
      );
      break;
    }

    case "result_publish": {
      if (p?.heat_id && p?.placements) {
        queryRun(
          `INSERT INTO published_results(event_id,heat_id,result_json,published_by,published_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_id) DO UPDATE SET
             result_json=excluded.result_json, published_by=excluded.published_by, published_at_ms=excluded.published_at_ms`,
          [op.event_id, p.heat_id, JSON.stringify(p.placements), op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    case "chairman_override": {
      if (p?.heat_id && p?.action) {
        const stateMap: Record<string, string> = {
          skip: "cancelled",
          recall: "on_floor",
          restart: "scheduled",
          complete: "completed",
        };
        const newStatus = stateMap[p.action as string] ?? (p.action as string);
        queryRun(
          `INSERT INTO heat_status(event_id,heat_id,status,updated_by,updated_at_ms)
           VALUES (?,?,?,?,?)
           ON CONFLICT(event_id,heat_id) DO UPDATE SET
             status=excluded.status, updated_by=excluded.updated_by, updated_at_ms=excluded.updated_at_ms`,
          [op.event_id, p.heat_id, newStatus, op.actor_device_id ?? null, now],
        );
      }
      break;
    }

    default:
      break;
  }

  db.exec("COMMIT");

  // 3. Broadcast to all connected peers (after COMMIT to avoid phantom ops)
  broadcastToEvent(op.event_id, { type: "op.applied", op });
  return { accepted: true };
  } catch (e) {
    try { db.exec("ROLLBACK"); } catch { /* already rolled back */ }
    console.error("[EventBox] applyOp error:", e);
    return { accepted: false, reason: "invalid" };
  }
}

// ---------------------------------------------------------------------------
// JSON response helper
// ---------------------------------------------------------------------------
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, authorization",
    },
  });
}

// Fix D: in-memory rate limit store for /auth/token
const tokenRateLimit = new Map<string, number[]>();

// Fix #6: Periodic rate-limit map cleanup (every 5 minutes)
setInterval(() => {
  const cutoff = Date.now() - 120_000; // entries older than 2 minutes
  for (const [key, timestamps] of tokenRateLimit) {
    const filtered = timestamps.filter((t) => t > cutoff);
    if (filtered.length === 0) {
      tokenRateLimit.delete(key);
    } else {
      tokenRateLimit.set(key, filtered);
    }
  }
}, 5 * 60_000);

// Fix #4/#6: Periodic op pruning — delete synced ops older than 24h
setInterval(() => {
  try {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    queryRun(`DELETE FROM ops WHERE synced_at IS NOT NULL AND received_at_ms < ?`, [cutoff]);
  } catch (e) {
    console.error("[EventBox] Op pruning error:", e);
  }
}, 60 * 60_000); // hourly

// ---------------------------------------------------------------------------
// HTTP + WS server
// ---------------------------------------------------------------------------
Deno.serve({ port: PORT }, async (req) => {
SERVER_START = Date.now(); // Reflect actual bind time on first request (close enough)
  const url = new URL(req.url);

  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type, authorization",
      },
    });
  }

  // ---- Root landing page — task-oriented dashboard with inline admin ----
  if (url.pathname === "/" && req.method === "GET") {
    const eventName = cachedEventName || EVENT_ID.slice(0, 8) + "…";
    const connectedDevices = (() => { let c = 0; for (const clients of wsClientsByEvent.values()) c += clients.size; return c; })();
    const heatCount = queryRows(`SELECT COUNT(*) FROM heat_status WHERE event_id=?`, [EVENT_ID])[0]?.[0] ?? 0;
    const opCount = queryRows(`SELECT COUNT(*) FROM ops WHERE event_id=?`, [EVENT_ID])[0]?.[0] ?? 0;
    const uptimeSec = Math.floor((Date.now() - SERVER_START) / 1000);
    const uptimeStr = uptimeSec < 60 ? `${uptimeSec}s` : uptimeSec < 3600 ? `${Math.floor(uptimeSec/60)}m` : `${Math.floor(uptimeSec/3600)}h ${Math.floor((uptimeSec%3600)/60)}m`;
    // Sync status
    let lastSyncStr = "Never";
    try {
      const syncRows = queryRows(`SELECT fetched_at FROM ref_data WHERE event_id=? ORDER BY fetched_at DESC LIMIT 1`, [EVENT_ID]);
      if (syncRows.length > 0) {
        const fetched = new Date(String(syncRows[0][0]));
        const ago = Math.floor((Date.now() - fetched.getTime()) / 1000);
        lastSyncStr = ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.floor(ago/60)}m ago` : `${Math.floor(ago/3600)}h ago`;
      }
    } catch {}
    const autoAuth = ADMIN_SECRET === ROOM_CODE;

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(eventName)} — EventBox</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;background:#0f172a;color:#e2e8f0;padding:1.5rem}
.wrap{max-width:520px;margin:0 auto}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem}
header h1{font-size:1.3rem;color:#fff;display:flex;align-items:center;gap:.5rem}
.live-badge{background:#22c55e20;color:#4ade80;font-size:.65rem;padding:2px 10px;border-radius:99px;font-weight:700;letter-spacing:.03em}
.online-count{font-size:.8rem;color:#94a3b8}
.event-sub{font-size:.75rem;color:#64748b;margin-top:2px}
.section{background:#1e293b;border-radius:12px;padding:1.25rem;margin-bottom:1rem}
.section-title{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem}
.section-title .icon{font-size:1rem}
/* Sync bar */
.sync-bar{display:flex;align-items:center;gap:.5rem;padding:.65rem .85rem;background:#1e293b;border-radius:10px;margin-bottom:1rem;font-size:.8rem}
.sync-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sync-dot.ok{background:#22c55e;box-shadow:0 0 6px #22c55e60}
.sync-dot.none{background:#f59e0b}
.sync-info{flex:1;color:#94a3b8}
.sync-info strong{color:#e2e8f0}
.sync-btn{background:none;border:1px solid #334155;color:#94a3b8;padding:3px 10px;border-radius:6px;font-size:.7rem;cursor:pointer}
.sync-btn:hover{background:#334155;color:#e2e8f0}
/* Live roster */
.roster-item{display:flex;align-items:center;gap:.65rem;padding:.5rem 0;border-bottom:1px solid #1a2744;font-size:.8rem}
.roster-item:last-child{border-bottom:none}
.avatar{width:30px;height:30px;border-radius:50%;background:#6366f130;color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.7rem;flex-shrink:0}
.roster-name{color:#fff;font-weight:500}
.role-badge{display:inline-block;background:#22c55e20;color:#4ade80;padding:1px 8px;border-radius:99px;font-size:.65rem;font-weight:600;margin-left:.35rem}
.presence-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;flex-shrink:0;margin-left:auto}
.no-sessions{color:#64748b;font-size:.8rem;padding:.75rem 0}
/* Invite staff */
.invite-form{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.75rem}
.invite-form select,.invite-form input{padding:.5rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff;font-size:.8rem;outline:none}
.invite-form select:focus,.invite-form input:focus{border-color:#6366f1}
.invite-form input{flex:1;min-width:120px}
.btn{padding:.5rem 1rem;border-radius:6px;border:none;font-size:.8rem;font-weight:600;cursor:pointer;transition:background .15s}
.btn-primary{background:#6366f1;color:#fff}.btn-primary:hover{background:#4f46e5}
.btn-danger{background:#dc2626;color:#fff;font-size:.7rem;padding:.3rem .6rem}.btn-danger:hover{background:#b91c1c}
.generated-qr{background:#fff;border-radius:8px;padding:.75rem;margin-top:.75rem;text-align:center}
.fallback-code{margin-top:.75rem;text-align:center;font-size:.8rem;color:#64748b}
.fallback-code strong{color:#f59e0b;font-family:monospace;font-size:1rem;letter-spacing:.3em}
/* Status grid */
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
.stat{background:#0f172a;border-radius:8px;padding:.65rem .75rem;text-align:center}
.stat .num{font-size:1.25rem;font-weight:700;color:#fff}
.stat .lbl{font-size:.65rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
details{margin-top:.75rem}
summary{font-size:.75rem;color:#64748b;cursor:pointer;padding:.5rem 0}
summary:hover{color:#94a3b8}
.tech-grid{font-family:monospace;font-size:.75rem;line-height:2;color:#94a3b8;word-break:break-all}
.tech-grid .val{color:#38bdf8}
.toast{position:fixed;bottom:1rem;left:50%;transform:translateX(-50%);background:#334155;color:#e2e8f0;padding:.5rem 1.25rem;border-radius:8px;font-size:.8rem;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.show{opacity:1}
.hidden{display:none}
/* Auth prompt */
.auth-overlay{position:fixed;inset:0;background:#0f172aee;display:flex;align-items:center;justify-content:center;z-index:50}
.auth-card{background:#1e293b;border-radius:16px;padding:2rem;max-width:360px;width:90%}
.auth-card h2{font-size:1.1rem;color:#fff;margin-bottom:.5rem}
.auth-card p{font-size:.8rem;color:#94a3b8;margin-bottom:1rem}
.auth-card .row{display:flex;gap:.5rem}
.auth-card input{flex:1;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff;font-size:.85rem;outline:none}
.auth-card input:focus{border-color:#6366f1}
.auth-error{color:#f87171;font-size:.8rem;margin-top:.5rem}
/* Skeleton loader */
.skeleton{background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:8px;height:2rem;margin:.5rem 0}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
</style></head>
<body>

<!-- Auth overlay (shown only if custom admin secret) -->
<div class="auth-overlay hidden" id="auth-overlay">
  <div class="auth-card">
    <h2>🔒 Admin Password</h2>
    <p>This server has a separate admin password. Enter it to manage staff.</p>
    <div class="row">
      <input type="password" id="admin-pwd" placeholder="Admin password" autofocus>
      <button class="btn btn-primary" onclick="authAdmin()">Unlock</button>
    </div>
    <div class="auth-error hidden" id="auth-error"></div>
  </div>
</div>

<div class="wrap">
<header>
  <div>
    <h1>${escapeHtml(eventName)}</h1>
    <div class="event-sub">EventBox v0.4 · up ${escapeHtml(uptimeStr)}</div>
  </div>
  <div style="text-align:right">
    <span class="live-badge">● Live</span>
    <div class="online-count" id="online-count">${connectedDevices} online</div>
  </div>
</header>

<!-- Sync status bar -->
<div class="sync-bar">
  <span class="sync-dot ${Number(heatCount) > 0 ? "ok" : "none"}"></span>
  <span class="sync-info"><strong>${heatCount} heats</strong> synced · last sync ${escapeHtml(lastSyncStr)}</span>
  <button class="sync-btn" onclick="refreshSync()">↻ Refresh</button>
</div>

<!-- Live Roster -->
<div class="section" id="roster-section">
  <div class="section-title"><span class="icon">👥</span> Staff on floor</div>
  <div id="roster-list">
    <div class="skeleton"></div><div class="skeleton" style="width:80%"></div>
  </div>
</div>

<!-- Invite Staff (inline admin) -->
<div class="section" id="invite-section">
  <div class="section-title"><span class="icon">➕</span> Invite Staff</div>
  <div class="invite-form">
    <select id="new-role">
      <option value="marshal">Marshal</option>
      <option value="judge">Judge</option>
      <option value="scanner">Scanner</option>
      <option value="announcer">Announcer</option>
      <option value="chairman">Chairman</option>
      <option value="deck_captain">Deck Captain</option>
      <option value="scrutineer">Scrutineer</option>
      <option value="dj">DJ</option>
      <option value="videographer">Videographer</option>
    </select>
    <input type="text" id="new-name" placeholder="Staff name">
    <button class="btn btn-primary" onclick="createSession()">Generate QR + link</button>
  </div>
  <div id="generated-code" class="hidden"></div>
  <div class="fallback-code">Or share room code: <strong>${escapeHtml(ROOM_CODE)}</strong></div>
  <div style="margin-top:.75rem;border-top:1px solid #334155;padding-top:.75rem">
    <div class="section-title" style="margin-bottom:.5rem"><span class="icon">📦</span> Import Event Data</div>
    <p style="font-size:.75rem;color:#64748b;margin-bottom:.5rem">Load a JSON file exported from ChasséFlow (for venues with no internet)</p>
    <input type="file" id="import-file" accept=".json" style="display:none" onchange="importFile(this)">
    <button class="btn btn-primary" style="font-size:.75rem;padding:.4rem .8rem" onclick="document.getElementById('import-file').click()">📂 Import from file</button>
    <span id="import-status" style="font-size:.75rem;color:#94a3b8;margin-left:.5rem"></span>
  </div>
</div>

<!-- Server Status -->
<div class="section">
  <div class="section-title"><span class="icon">📊</span> Server Status</div>
  <div class="stat-grid">
    <div class="stat"><div class="num">${connectedDevices}</div><div class="lbl">Connected</div></div>
    <div class="stat"><div class="num">${heatCount}</div><div class="lbl">Heats</div></div>
    <div class="stat"><div class="num">${opCount}</div><div class="lbl">Ops</div></div>
    <div class="stat"><div class="num">${escapeHtml(uptimeStr)}</div><div class="lbl">Uptime</div></div>
  </div>
  <details>
    <summary>Technical details</summary>
    <div class="tech-grid">
      Event ID: <span class="val" style="cursor:pointer" onclick="navigator.clipboard.writeText(${JSON.stringify(EVENT_ID)}).then(()=>showToast('Copied!'))">${escapeHtml(EVENT_ID)}</span><br>
      Port: <span class="val">${escapeHtml(String(PORT))}</span><br>
      Database: <span class="val">${escapeHtml(DB_PATH)}</span><br>
      Version: <span class="val">0.4.0</span>
    </div>
  </details>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
let adminToken=sessionStorage.getItem('eventbox_admin_token')||'';
const ROOM_CODE=${JSON.stringify(ROOM_CODE)};
const autoAuth=${autoAuth ? "true" : "false"};

function showToast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

// --- Auth flow ---
async function doAutoAuth(){
  const did=localStorage.getItem('device_id')||crypto.randomUUID();
  localStorage.setItem('device_id',did);
  try{
    const r=await fetch('/auth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({device_id:did,admin_secret:ROOM_CODE})});
    const d=await r.json();
    if(r.ok){adminToken=d.token;sessionStorage.setItem('eventbox_admin_token',adminToken);return true}
  }catch{}
  return false;
}

async function handleAuth(){
  if(adminToken){
    // Verify cached token is still valid
    try{
      const r=await fetch('/api/staff-sessions',{headers:{'authorization':'Bearer '+adminToken}});
      if(r.ok){loadRoster(await r.json());return}
    }catch{}
    // Token stale — clear and retry
    adminToken='';sessionStorage.removeItem('eventbox_admin_token');
  }
  if(autoAuth){
    const ok=await doAutoAuth();
    if(ok){loadRoster();return}
  }
  // Show password prompt
  document.getElementById('auth-overlay').classList.remove('hidden');
}

async function authAdmin(){
  const pwd=document.getElementById('admin-pwd').value.trim();
  const did=localStorage.getItem('device_id')||crypto.randomUUID();
  localStorage.setItem('device_id',did);
  try{
    const r=await fetch('/auth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({device_id:did,admin_secret:pwd})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Auth failed');
    adminToken=d.token;sessionStorage.setItem('eventbox_admin_token',adminToken);
    document.getElementById('auth-overlay').classList.add('hidden');
    loadRoster();
  }catch(e){
    const el=document.getElementById('auth-error');
    el.classList.remove('hidden');el.textContent=e.message;
  }
}
document.getElementById('admin-pwd')?.addEventListener('keydown',e=>{if(e.key==='Enter')authAdmin()});

// --- Roster ---
async function loadRoster(cachedData){
  try{
    let data=cachedData;
    if(!data){
      const r=await fetch('/api/staff-sessions',{headers:{'authorization':'Bearer '+adminToken}});
      if(r.status===401){adminToken='';sessionStorage.removeItem('eventbox_admin_token');handleAuth();return}
      data=await r.json();
    }
    const list=document.getElementById('roster-list');
    const sessions=(data.sessions||[]).filter(s=>!s.revoked_at);
    if(sessions.length===0){
      list.innerHTML='<div class="no-sessions">No staff connected yet. Create a join code above or share the room code.</div>';
      return;
    }
    list.innerHTML=sessions.map(s=>{
      const initials=(s.staff_name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
      return '<div class="roster-item"><div class="avatar">'+esc(initials)+'</div><div><span class="roster-name">'+esc(s.staff_name)+'</span><span class="role-badge">'+esc(s.role)+'</span></div><span class="presence-dot"></span><button class="btn btn-danger" style="margin-left:.5rem" onclick="revoke(\\''+s.id+'\\')">Revoke</button></div>';
    }).join('');
  }catch(e){
    document.getElementById('roster-list').innerHTML='<div class="no-sessions" style="color:#f87171">'+esc(e.message)+'</div>';
  }
}

// Poll roster every 5s
setInterval(()=>{if(adminToken)loadRoster()},5000);

// --- Create session ---
async function createSession(){
  const role=document.getElementById('new-role').value;
  const name=document.getElementById('new-name').value.trim();
  if(!name){showToast('Enter a staff name');return}
  try{
    const r=await fetch('/api/staff-sessions',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+adminToken},body:JSON.stringify({role,staff_name:name})});
    if(r.status===401){adminToken='';sessionStorage.removeItem('eventbox_admin_token');handleAuth();return}
    const d=await r.json();
    if(!r.ok)throw new Error(d.error);
    document.getElementById('new-name').value='';
    // Show generated QR
    const tokenUrl=location.origin+'/staff/join?token='+encodeURIComponent(d.join_code);
    const container=document.getElementById('generated-code');
    container.classList.remove('hidden');
    container.innerHTML='<div class="generated-qr" id="gen-qr"></div><div style="text-align:center;margin-top:.5rem;font-size:.75rem;color:#94a3b8">'+esc(d.staff_name)+' · '+esc(d.role)+'<br><span style="font-family:monospace;color:#38bdf8;cursor:pointer" onclick="navigator.clipboard.writeText(\\''+tokenUrl+'\\').then(()=>showToast(\\'Link copied!\\'))">'+esc(tokenUrl)+'</span></div>';
    // Generate QR
    if(window.qrcode){drawQR(tokenUrl,'gen-qr')}
    else{const s=document.createElement('script');s.src='https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';s.onload=function(){drawQR(tokenUrl,'gen-qr')};document.head.appendChild(s)}
    showToast('Code created for '+name);
    loadRoster();
  }catch(e){showToast('Error: '+e.message)}
}

async function revoke(id){
  if(!confirm('Revoke this session?'))return;
  try{
    await fetch('/api/staff-sessions/revoke',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+adminToken},body:JSON.stringify({session_id:id})});
    loadRoster();
  }catch(e){showToast('Error: '+e.message)}
}

// --- File import ---
async function importFile(input){
  const file=input.files[0];
  if(!file)return;
  const status=document.getElementById('import-status');
  status.textContent='Importing…';status.style.color='#94a3b8';
  try{
    const text=await file.text();
    const data=JSON.parse(text);
    if(!data.tables||!Array.isArray(data.tables))throw new Error('Invalid format — expected { tables: [...] }');
    const r=await fetch('/api/sync-ref',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+adminToken},body:text});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Import failed');
    status.textContent='✓ Imported '+d.synced+' tables';status.style.color='#4ade80';
    showToast('Event data imported!');
    setTimeout(()=>location.reload(),1500);
  }catch(e){
    status.textContent='✗ '+e.message;status.style.color='#f87171';
  }
  input.value='';
}

// --- Sync refresh ---
async function refreshSync(){
  showToast('Refreshing stats…');
  setTimeout(()=>location.reload(),500);
}

// --- QR helper ---
function drawQR(url,containerId){
  const qr=qrcode(0,'L');qr.addData(url);qr.make();
  document.getElementById(containerId).innerHTML=qr.createImgTag(4,6);
}

// --- Init ---
handleAuth();
</script>
</body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // ---- Health (unauthenticated — needed for discovery) ----
  if (url.pathname === "/health") {
    return json({
      ok: true,
      time: Date.now(),
      event_id: EVENT_ID,
      version: "0.4.0",
    });
  }

  // ---- Auth: issue token via room code (Fix D: rate-limited) ----
  if (url.pathname === "/auth/token" && req.method === "POST") {
    // Rate limit: max 10 attempts per IP per minute
    const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const rlKey = `token:${clientIp}`;
    const now = Date.now();
    if (!tokenRateLimit.has(rlKey)) tokenRateLimit.set(rlKey, []);
    const attempts = tokenRateLimit.get(rlKey)!;
    // Prune old entries
    while (attempts.length > 0 && attempts[0] < now - 60_000) attempts.shift();
    if (attempts.length >= 10) {
      return json({ ok: false, error: "rate_limited", retry_after_ms: 60_000 - (now - attempts[0]) }, 429);
    }
    attempts.push(now);

    const body = await req.json().catch(() => null);
    const deviceId = body?.device_id ?? crypto.randomUUID();

    // Derive role securely — never trust client-supplied role
    let role = "viewer";
    let staffSessionId: string | undefined;

    // Check admin_secret FIRST — grants event_admin without needing room_code
    if (body?.admin_secret && body.admin_secret === ADMIN_SECRET) {
      role = "event_admin";
    } else if (body?.room_code !== ROOM_CODE) {
      // room_code is required for non-admin auth
      return json({ ok: false, error: "invalid_room_code" }, 401);
    } else if (body.staff_session_id) {
      // Look up role from staff_sessions table
      const sessionRows = queryRows(
        `SELECT id, role, revoked_at, expires_at FROM staff_sessions WHERE id=? AND event_id=?`,
        [body.staff_session_id, EVENT_ID],
      );
      if (sessionRows.length === 0) {
        return json({ ok: false, error: "invalid_staff_session" }, 401);
      }
      const [id, sessionRole, revokedAt, expiresAt] = sessionRows[0];
      if (revokedAt) {
        return json({ ok: false, error: "session_revoked" }, 401);
      }
      if (Number(expiresAt) < Date.now()) {
        return json({ ok: false, error: "session_expired" }, 401);
      }
      role = String(sessionRole);
      staffSessionId = String(id);
    }
    // Otherwise: role stays "viewer" (read-only, no write permissions)

    const token = await issueToken(deviceId, role, staffSessionId);
    return json({
      ok: true,
      token,
      event_id: EVENT_ID,
      expires_in_ms: TOKEN_TTL_MS,
    });
  }

  // ---- Whoami (debug) ----
  if (url.pathname === "/whoami" && req.method === "GET") {
    const claims = await authenticate(req);
    if (!claims) return json({ ok: false, error: "unauthorized" }, 401);
    return json({ ok: true, claims });
  }

  // ---- Ops batch ingest ----
  if (url.pathname === "/ops/batch" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const body = await req.json().catch(() => null);
    if (!body || !Array.isArray(body.ops)) {
      return json({ error: "invalid body — expected { ops: [...] }" }, 400);
    }

    const results: Array<{ op_id: string | null; accepted: boolean; reason?: string }> = [];
    for (const raw of body.ops) {
      if (!raw?.op_id || !raw?.event_id || !raw?.op_type || !raw?.created_at_ms) {
        results.push({ op_id: raw?.op_id ?? null, accepted: false, reason: "invalid" });
        continue;
      }

      const op: Op = {
        op_id: String(raw.op_id),
        event_id: EVENT_ID,
        op_type: String(raw.op_type),
        created_at_ms: Number(raw.created_at_ms),
        actor_device_id: claims.device_id,
        actor_role: claims.role ?? raw.actor_role,
        entity_type: raw.entity_type ? String(raw.entity_type) : undefined,
        entity_id: raw.entity_id ? String(raw.entity_id) : undefined,
        payload: raw.payload ?? {},
      };
      const r = applyOp(op);
      results.push({ op_id: op.op_id, ...r });
    }

    return json({ ok: true, results });
  }

  // ---- State read endpoints ----
  if (url.pathname.startsWith("/state/") && req.method === "GET") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const parts = url.pathname.split("/").filter(Boolean);
    const kind = parts[1];

    switch (kind) {
      case "checkins": {
        const rows = queryRows(
          `SELECT credential_id, status, updated_at_ms FROM checkins WHERE event_id=?`,
          [EVENT_ID],
        ).map(([credential_id, status, updated_at_ms]) => ({
          credential_id, status, updated_at_ms,
        }));
        return json({ event_id: EVENT_ID, checkins: rows });
      }

      case "marshal": {
        const rows = queryRows(
          `SELECT heat_entry_id, status, updated_by, updated_at_ms FROM marshal_status WHERE event_id=?`,
          [EVENT_ID],
        ).map(([heat_entry_id, status, updated_by, updated_at_ms]) => ({
          heat_entry_id, status, updated_by, updated_at_ms,
        }));
        return json({ event_id: EVENT_ID, marshal: rows });
      }

      case "heats": {
        const rows = queryRows(
          `SELECT heat_id, status, updated_by, updated_at_ms FROM heat_status WHERE event_id=?`,
          [EVENT_ID],
        ).map(([heat_id, status, updated_by, updated_at_ms]) => ({
          heat_id, status, updated_by, updated_at_ms,
        }));
        return json({ event_id: EVENT_ID, heats: rows });
      }

      case "marks": {
        const heatId = url.searchParams.get("heat_id");
        const query = heatId
          ? `SELECT heat_id,dance_code,judge_assignment_id,heat_entry_id,mark_type,mark_value,updated_at_ms FROM judge_marks WHERE event_id=? AND heat_id=?`
          : `SELECT heat_id,dance_code,judge_assignment_id,heat_entry_id,mark_type,mark_value,updated_at_ms FROM judge_marks WHERE event_id=?`;
        const params = heatId ? [EVENT_ID, heatId] : [EVENT_ID];
        const rows = queryRows(query, params).map(
          ([heat_id, dance_code, judge_assignment_id, heat_entry_id, mark_type, mark_value, updated_at_ms]) => ({
            heat_id, dance_code, judge_assignment_id, heat_entry_id,
            mark_type, mark_value: JSON.parse(String(mark_value)),
            updated_at_ms,
          }),
        );
        return json({ event_id: EVENT_ID, marks: rows });
      }

      case "submissions": {
        const rows = queryRows(
          `SELECT heat_id,dance_code,judge_assignment_id,submitted_at_ms FROM judge_submissions WHERE event_id=?`,
          [EVENT_ID],
        ).map(([heat_id, dance_code, judge_assignment_id, submitted_at_ms]) => ({
          heat_id, dance_code, judge_assignment_id, submitted_at_ms,
        }));
        return json({ event_id: EVENT_ID, submissions: rows });
      }

      case "scratches": {
        const rows = queryRows(
          `SELECT heat_entry_id, reason, requested_by, requested_at FROM scratches WHERE event_id=?`,
          [EVENT_ID],
        ).map(([heat_entry_id, reason, requested_by, requested_at]) => ({
          heat_entry_id, reason, requested_by, requested_at,
        }));
        return json({ event_id: EVENT_ID, scratches: rows });
      }

      case "nowplaying": {
        const rows = queryRows(
          `SELECT heat_id, heat_number, division_name, dance_code, status, updated_at_ms FROM now_playing WHERE event_id=?`,
          [EVENT_ID],
        );
        const np = rows.length > 0
          ? {
            heat_id: rows[0][0], heat_number: rows[0][1],
            division_name: rows[0][2], dance_code: rows[0][3],
            status: rows[0][4], updated_at_ms: rows[0][5],
          }
          : null;
        return json({ event_id: EVENT_ID, now_playing: np });
      }

      case "results": {
        const heatId = url.searchParams.get("heat_id");
        const query = heatId
          ? `SELECT heat_id, result_json, published_by, published_at_ms FROM published_results WHERE event_id=? AND heat_id=?`
          : `SELECT heat_id, result_json, published_by, published_at_ms FROM published_results WHERE event_id=?`;
        const params = heatId ? [EVENT_ID, heatId] : [EVENT_ID];
        const rows = queryRows(query, params).map(
          ([heat_id, result_json, published_by, published_at_ms]) => ({
            heat_id, placements: JSON.parse(String(result_json)),
            published_by, published_at_ms,
          }),
        );
        return json({ event_id: EVENT_ID, results: rows });
      }

      case "ref": {
        const table = url.searchParams.get("table") || "";
        if (!table) return json({ error: "table param required" }, 400);
        const rows = queryRows(
          `SELECT data_json, fetched_at FROM ref_data WHERE event_id=? AND table_name=?`,
          [EVENT_ID, table],
        );
        if (rows.length === 0) return json({ data: null });
        return json({ data: rows[0][0], fetched_at: rows[0][1] });
      }

      default:
        return json({ error: `unknown state kind: ${kind}` }, 404);
    }
  }

  // ---- Ops history (for upstream sync) ----
  if (url.pathname === "/ops/unsynced" && req.method === "GET") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const limit = Number(url.searchParams.get("limit") ?? 500);
    const rows = queryRows(
      `SELECT op_id, event_id, op_type, entity_type, entity_id, payload_json, created_at_ms, received_at_ms
       FROM ops WHERE synced_at IS NULL ORDER BY received_at_ms ASC LIMIT ?`,
      [limit],
    ).map(([op_id, event_id, op_type, entity_type, entity_id, payload_json, created_at_ms, received_at_ms]) => ({
      op_id, event_id, op_type, entity_type, entity_id,
      payload: JSON.parse(String(payload_json)),
      created_at_ms, received_at_ms,
    }));
    return json({ ops: rows });
  }

  if (url.pathname === "/ops/mark-synced" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const body = await req.json().catch(() => null);
    if (!body?.op_ids || !Array.isArray(body.op_ids)) {
      return json({ error: "expected { op_ids: [...] }" }, 400);
    }
    const now = new Date().toISOString();
    for (const id of body.op_ids) {
      queryRun(`UPDATE ops SET synced_at=? WHERE op_id=?`, [now, String(id)]);
    }
    return json({ ok: true, marked: body.op_ids.length });
  }

  // ---- Fix #4: POST /api/sync-ref — Accept reference data for local portals ----
  if (url.pathname === "/api/sync-ref" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const body = await req.json().catch(() => null);
    if (!body || !Array.isArray(body.tables)) {
      return json({ error: "expected { tables: [{ name, data }] }" }, 400);
    }

    const now = new Date().toISOString();
    let count = 0;
    for (const t of body.tables) {
      if (!t?.name || t.data === undefined) continue;
      queryRun(
        `INSERT INTO ref_data(event_id, table_name, data_json, fetched_at)
         VALUES (?,?,?,?)
         ON CONFLICT(event_id, table_name) DO UPDATE SET
           data_json=excluded.data_json, fetched_at=excluded.fetched_at`,
        [EVENT_ID, t.name, JSON.stringify(t.data), now],
      );
      count++;
    }
    // Refresh cached event name if event table was synced
    if (body.tables.some((t: { name?: string }) => t?.name === "event")) {
      refreshCachedEventName();
    }
    return json({ ok: true, synced: count });
  }

  // ---- WebSocket ----
  if (url.pathname === "/ws") {
    const token = url.searchParams.get("token");
    if (!token) return json({ error: "missing token query param" }, 401);
    const claims = await verifyToken(token);
    if (!claims) return json({ error: "invalid or expired token" }, 401);

    const { socket, response } = Deno.upgradeWebSocket(req);

    let set = wsClientsByEvent.get(EVENT_ID);
    if (!set) wsClientsByEvent.set(EVENT_ID, (set = new Set()));

    socket.onopen = () => {
      set!.add(socket);
      socket.send(JSON.stringify({
        type: "connected",
        event_id: EVENT_ID,
        device_id: claims.device_id,
        role: claims.role,
        server_time: Date.now(),
        version: "0.4.0",
      }));
    };

    socket.onclose = () => {
      set?.delete(socket);
    };

    socket.onmessage = (e) => {
      try {
        const m = JSON.parse(e.data);
        if (m?.type === "ping") {
          socket.send(JSON.stringify({ type: "pong", time: Date.now() }));
        }
        if (m?.type === "op" && m?.op) {
          const op: Op = {
            ...m.op,
            event_id: EVENT_ID,
            actor_device_id: claims.device_id,
            actor_role: claims.role ?? m.op.actor_role,
          };
          const result = applyOp(op);
          socket.send(JSON.stringify({ type: "op.result", op_id: op.op_id, ...result }));
        }
      } catch { /* invalid message */ }
    };

    return response;
  }

  // ---- Staff Sessions (BYOD) ----

  function generateJoinCode(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(6)))
      .map((b) => (b % 36).toString(36))
      .join("")
      .toUpperCase();
  }

  // POST /api/staff-sessions — Create a staff session (admin auth required)
  if (url.pathname === "/api/staff-sessions" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);
    if (claims.role !== "event_admin" || claims.staff_session_id) {
      return json({ error: "forbidden -- admin token required" }, 403);
    }

    const body = await req.json().catch(() => null);
    if (!body?.role || !body?.staff_name) {
      return json({ error: "role and staff_name required" }, 400);
    }

    const id = crypto.randomUUID();
    const joinCode = generateJoinCode();
    const now = Date.now();
    const expiresAt = now + 12 * 60 * 60 * 1000;

    queryRun(
      `INSERT INTO staff_sessions(id, event_id, role, staff_name, join_code, created_at, expires_at) VALUES(?,?,?,?,?,?,?)`,
      [id, EVENT_ID, body.role, body.staff_name, joinCode, now, expiresAt],
    );

    const joinUrl = `${url.origin}/staff/join?token=${encodeURIComponent(joinCode)}`;
    return json({ id, join_code: joinCode, join_url: joinUrl, role: body.role, staff_name: body.staff_name, expires_at: expiresAt });
  }

  // POST /api/staff-sessions/join — Volunteer claims a code (NO auth required)
  // Accepts EITHER a per-staff join_code OR the universal ROOM_CODE
  if (url.pathname === "/api/staff-sessions/join" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    if (!body?.join_code) {
      return json({ error: "join_code required" }, 400);
    }

    const code = body.join_code.trim().toUpperCase();
    const incomingDeviceId = body.device_id || crypto.randomUUID();

    // --- Universal room code join: create an ad-hoc staff session ---
    if (code === ROOM_CODE) {
      const shortId = incomingDeviceId.slice(0, 4).toUpperCase();
      const staffName = body.staff_name || `Staff-${shortId}`;
      const role = body.role || "marshal";
      const id = crypto.randomUUID();
      const joinCode = generateJoinCode();
      const now = Date.now();
      const expiresAt = now + TOKEN_TTL_MS;

      queryRun(
        `INSERT INTO staff_sessions(id, event_id, role, staff_name, join_code, device_id, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?)`,
        [id, EVENT_ID, role, staffName, joinCode, incomingDeviceId, now, expiresAt],
      );

      const token = await issueToken(incomingDeviceId, role, id);
      return json({
        token,
        staff_session_id: id,
        event_id: EVENT_ID,
        role,
        staff_name: staffName,
        expires_at: expiresAt,
      });
    }

    // --- Per-staff join code lookup ---
    const rows = queryRows(
      `SELECT id, event_id, role, staff_name, expires_at, revoked_at FROM staff_sessions WHERE join_code=?`,
      [code],
    );

    if (rows.length === 0) return json({ error: "Invalid code. Enter the Room Code shown on the EventBox dashboard, or a personal join code from your admin." }, 404);
    const [id, eventId, role, staffName, expiresAt, revokedAt] = rows[0];

    if (revokedAt) return json({ error: "This session has been revoked" }, 403);
    if (Number(expiresAt) < Date.now()) return json({ error: "This join code has expired" }, 403);

    // Bug 4 fix: allow device re-claim (soft re-claim) — update device_id unconditionally
    queryRun(`UPDATE staff_sessions SET device_id=? WHERE id=?`, [incomingDeviceId, id]);

    const token = await issueToken(incomingDeviceId, String(role), String(id));

    return json({
      token,
      staff_session_id: id,
      event_id: eventId,
      role,
      staff_name: staffName,
      expires_at: Number(expiresAt),
    });
  }

  // GET /api/staff-sessions — List active sessions (admin auth required)
  if (url.pathname === "/api/staff-sessions" && req.method === "GET") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);
    if (claims.role !== "event_admin" || claims.staff_session_id) {
      return json({ error: "forbidden -- admin token required" }, 403);
    }

    const rows = queryRows(
      `SELECT id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at FROM staff_sessions WHERE event_id=? AND revoked_at IS NULL ORDER BY created_at DESC`,
      [EVENT_ID],
    ).map(([id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at]) => ({
      id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at,
    }));

    return json({ event_id: EVENT_ID, sessions: rows });
  }

  // POST /api/staff-sessions/revoke — Revoke a session (admin auth required)
  if (url.pathname === "/api/staff-sessions/revoke" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);
    if (claims.role !== "event_admin" || claims.staff_session_id) {
      return json({ error: "forbidden -- admin token required" }, 403);
    }

    const body = await req.json().catch(() => null);
    if (!body?.session_id) return json({ error: "session_id required" }, 400);

    queryRun(`UPDATE staff_sessions SET revoked_at=? WHERE id=? AND event_id=?`, [Date.now(), body.session_id, EVENT_ID]);
    return json({ ok: true });
  }

  // GET /staff/join — Two paths: token-based scan-and-go OR manual room code
  if (url.pathname === "/staff/join" && req.method === "GET") {
    const joinCode = url.searchParams.get("join") || "";
    const tokenParam = url.searchParams.get("token") || "";
    const eventName = cachedEventName || EVENT_ID.slice(0, 8) + "…";
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Staff Join</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:16px;padding:2rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{font-size:1.3rem;color:#fff;text-align:center;margin-bottom:.25rem}
.subtitle{text-align:center;color:#94a3b8;font-size:.8rem;margin-bottom:1.25rem}
.steps{display:flex;justify-content:center;gap:.5rem;margin-bottom:1.5rem}
.step{width:32px;height:4px;border-radius:2px;background:#334155;transition:background .3s}
.step.active{background:#6366f1}
.step.done{background:#22c55e}
label{display:block;font-size:.75rem;color:#94a3b8;margin-bottom:.35rem;text-transform:uppercase;letter-spacing:.05em}
input{width:100%;padding:.75rem;border-radius:8px;border:2px solid #334155;background:#0f172a;color:#fff;font-size:1rem;outline:none;transition:border-color .2s}
input:focus{border-color:#6366f1}
input.code-input{font-size:1.5rem;text-align:center;letter-spacing:.3em}
.role-grid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin:.75rem 0}
.role-btn{padding:.65rem;border-radius:8px;border:2px solid #334155;background:transparent;color:#e2e8f0;font-size:.8rem;cursor:pointer;text-align:center;transition:all .15s;font-weight:500}
.role-btn:hover{border-color:#6366f1;background:#6366f120}
.role-btn.selected{border-color:#6366f1;background:#6366f130;color:#a5b4fc}
.role-btn .emoji{font-size:1.1rem;display:block;margin-bottom:2px}
button.primary{width:100%;padding:.75rem;border-radius:8px;border:none;background:#6366f1;color:#fff;font-size:.9rem;cursor:pointer;font-weight:600;transition:background .15s;margin-top:.75rem}
button.primary:hover{background:#4f46e5}
button.primary:disabled{opacity:.4;cursor:not-allowed}
.msg{margin-top:.75rem;font-size:.8rem;text-align:center;min-height:1em}
.msg.error{color:#f87171}.msg.success{color:#4ade80}.msg.loading{color:#94a3b8}
.back{display:block;text-align:center;margin-top:1.25rem;color:#818cf8;font-size:.8rem;text-decoration:none}
.back:hover{text-decoration:underline}
.hidden{display:none}
.role-badge{display:inline-block;background:#22c55e20;color:#4ade80;padding:2px 10px;border-radius:99px;font-size:.75rem;font-weight:600}
/* Token welcome card */
.welcome{text-align:center}
.welcome .avatar-lg{width:64px;height:64px;border-radius:50%;background:#6366f130;color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1.5rem;margin:0 auto 1rem}
.welcome h2{color:#fff;font-size:1.2rem;margin-bottom:.25rem}
.welcome .event-name{color:#94a3b8;font-size:.8rem;margin-bottom:1rem}
.spinner{display:inline-block;width:20px;height:20px;border:3px solid #334155;border-top:3px solid #6366f1;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head>
<body><div class="card">

<!-- Token path: auto-join loading -->
<div id="token-loading" class="hidden" style="text-align:center;padding:2rem 0">
  <div class="spinner"></div>
  <p style="margin-top:1rem;color:#94a3b8;font-size:.85rem">Connecting…</p>
</div>

<!-- Token path: welcome screen -->
<div id="token-welcome" class="hidden">
  <div class="welcome">
    <div class="avatar-lg" id="welcome-avatar">?</div>
    <h2 id="welcome-name">Welcome!</h2>
    <div><span class="role-badge" id="welcome-role"></span></div>
    <div class="event-name">${escapeHtml(eventName)}</div>
    <button class="primary" id="welcome-btn" onclick="openPortal()">Open console →</button>
  </div>
</div>

<!-- Manual path: step 1 (room code) -->
<div id="step1" class="hidden">
  <h1>Join Staff Portal</h1>
  <p class="subtitle">Connect to EventBox on this network</p>
  <div class="steps"><div class="step active" id="s1"></div><div class="step" id="s2"></div></div>
  <label>Room Code</label>
  <input class="code-input" id="code" placeholder="000000" maxlength="8" value="${escapeHtml(joinCode)}" autofocus>
  <button class="primary" id="btn1" onclick="validateCode()">Continue →</button>
</div>

<!-- Manual path: step 2 (role + name) -->
<div id="step2" class="hidden">
  <h1>Join Staff Portal</h1>
  <p class="subtitle">${escapeHtml(eventName)}</p>
  <div class="steps"><div class="step done" id="s1b"></div><div class="step active" id="s2b"></div></div>
  <label>Your name</label>
  <input id="staff-name" placeholder="e.g. Sarah, Mike T.">
  <label style="margin-top:.75rem">Your role</label>
  <div class="role-grid">
    <button class="role-btn selected" data-role="marshal" onclick="pickRole(this)"><span class="emoji">🎯</span>Marshal</button>
    <button class="role-btn" data-role="judge" onclick="pickRole(this)"><span class="emoji">📋</span>Judge</button>
    <button class="role-btn" data-role="scanner" onclick="pickRole(this)"><span class="emoji">📷</span>Scanner</button>
    <button class="role-btn" data-role="announcer" onclick="pickRole(this)"><span class="emoji">🎙️</span>Announcer</button>
    <button class="role-btn" data-role="deck_captain" onclick="pickRole(this)"><span class="emoji">🚦</span>Deck Captain</button>
    <button class="role-btn" data-role="dj" onclick="pickRole(this)"><span class="emoji">🎵</span>DJ</button>
  </div>
  <button class="primary" id="btn2" onclick="joinNow()">Join as Marshal →</button>
</div>

<div class="msg" id="msg"></div>
<a class="back" href="/">← Back to Dashboard</a>
</div>
<script>
const msg=document.getElementById('msg');
let selectedRole='marshal';
let validatedCode='';
let joinData=null;

// Decide which path to show
const tokenParam=${JSON.stringify(tokenParam)};
const joinParam=${JSON.stringify(joinCode)};

if(tokenParam){
  // Token path: auto-join immediately
  document.getElementById('token-loading').classList.remove('hidden');
  tokenJoin(tokenParam);
}else{
  // Manual path
  document.getElementById('step1').classList.remove('hidden');
  if(joinParam)setTimeout(validateCode,300);
}

async function tokenJoin(code){
  try{
    const did=localStorage.getItem('device_id')||crypto.randomUUID();
    localStorage.setItem('device_id',did);
    const r=await fetch('/api/staff-sessions/join',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({join_code:code,device_id:did})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Join failed');
    localStorage.setItem('eventbox_staff_session',JSON.stringify(d));
    localStorage.setItem('eventbox_base_url',location.origin);
    joinData=d;
    // Show welcome
    document.getElementById('token-loading').classList.add('hidden');
    document.getElementById('token-welcome').classList.remove('hidden');
    const initials=(d.staff_name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    document.getElementById('welcome-avatar').textContent=initials;
    document.getElementById('welcome-name').textContent='Welcome, '+d.staff_name+'!';
    document.getElementById('welcome-role').textContent=d.role;
  }catch(e){
    document.getElementById('token-loading').classList.add('hidden');
    document.getElementById('step1').classList.remove('hidden');
    showMsg('error','Token expired or invalid — enter room code manually');
  }
}

function openPortal(){
  if(!joinData)return;
  const url=location.origin+'/portal?role='+encodeURIComponent(joinData.role)+'&eventId='+joinData.event_id+'&token='+encodeURIComponent(joinData.token);
  location.href=url;
}

function pickRole(btn){
  document.querySelectorAll('.role-btn').forEach(b=>b.classList.remove('selected'));
  btn.classList.add('selected');
  selectedRole=btn.dataset.role;
  document.getElementById('btn2').textContent='Join as '+btn.textContent.trim()+' →';
}

document.getElementById('code')?.addEventListener('keydown',e=>{if(e.key==='Enter')validateCode()});
document.getElementById('staff-name')?.addEventListener('keydown',e=>{if(e.key==='Enter')joinNow()});

async function validateCode(){
  const code=document.getElementById('code').value.trim();
  if(!code){showMsg('error','Enter the room code');return}
  showMsg('loading','Checking…');
  try{
    const r=await fetch('/auth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({room_code:code,device_id:localStorage.getItem('device_id')||crypto.randomUUID()})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error==='invalid_room_code'?'Invalid room code':d.error||'Failed');
    validatedCode=code;
    showMsg('','');
    document.getElementById('step1').classList.add('hidden');
    document.getElementById('step2').classList.remove('hidden');
    document.getElementById('staff-name').focus();
  }catch(e){showMsg('error',e.message)}
}

async function joinNow(){
  const name=document.getElementById('staff-name').value.trim()||('Staff-'+crypto.randomUUID().slice(0,4).toUpperCase());
  showMsg('loading','Connecting…');
  document.getElementById('btn2').disabled=true;
  try{
    const did=localStorage.getItem('device_id')||crypto.randomUUID();
    localStorage.setItem('device_id',did);
    const r=await fetch('/api/staff-sessions/join',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({join_code:validatedCode,device_id:did,role:selectedRole,staff_name:name})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Join failed');
    localStorage.setItem('eventbox_staff_session',JSON.stringify(d));
    localStorage.setItem('eventbox_base_url',location.origin);
    joinData=d;
    const localPortalUrl=location.origin+'/portal?role='+encodeURIComponent(d.role)+'&eventId='+d.event_id+'&token='+encodeURIComponent(d.token);
    showMsg('success','');
    msg.innerHTML='✅ Welcome, <strong>'+esc(d.staff_name)+'</strong>! <span class="role-badge">'+esc(d.role)+'</span>';
    setTimeout(()=>{location.href=localPortalUrl},1500);
  }catch(e){showMsg('error',e.message);document.getElementById('btn2').disabled=false}
}

function showMsg(cls,txt){msg.className='msg'+(cls?' '+cls:'');msg.textContent=txt}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // GET /staff — Staff portal entry point (redirect to join)
  if (url.pathname === "/staff" && req.method === "GET") {
    const joinCode = url.searchParams.get("join") || "";
    if (joinCode) {
      return Response.redirect(`${url.origin}/staff/join?join=${encodeURIComponent(joinCode)}`, 302);
    }
    return Response.redirect(`${url.origin}/staff/join`, 302);
  }

  // ---- Auth: refresh token (Bug 3 fix) ----
  if (url.pathname === "/auth/refresh" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    const sessionId = body?.staff_session_id;
    if (!sessionId) return json({ error: "staff_session_id required" }, 400);

    const rows = queryRows(
      `SELECT id, event_id, role, device_id, expires_at, revoked_at FROM staff_sessions WHERE id=?`,
      [sessionId],
    );
    if (rows.length === 0) return json({ error: "Session not found" }, 404);
    const [id, , role, storedDeviceId, expiresAt, revokedAt] = rows[0];
    if (revokedAt) return json({ error: "Session revoked" }, 403);

    // Fix 2: reject if session already expired (no grace)
    if (Number(expiresAt) < Date.now()) {
      return json({ error: "Session expired — re-join with your code" }, 403);
    }

    // Fix 2: require device_id match
    const incomingDeviceId = body?.device_id;
    if (incomingDeviceId && storedDeviceId && String(incomingDeviceId) !== String(storedDeviceId)) {
      return json({ error: "Device mismatch — re-join from your device" }, 403);
    }

    // Extend expiry
    const newExpiry = Date.now() + TOKEN_TTL_MS;
    queryRun(`UPDATE staff_sessions SET expires_at=? WHERE id=?`, [newExpiry, id]);

    const token = await issueToken(String(storedDeviceId ?? ""), String(role), String(id));
    return json({ ok: true, token, expires_at: newExpiry });
  }

  // ---- GET /admin — Redirect to dashboard (admin is now inline) ----
  if (url.pathname === "/admin" && req.method === "GET") {
    return Response.redirect(`${url.origin}/`, 302);
  }

  // ---- GET /portal — Local staff portal (works fully offline on LAN) ----
  if (url.pathname === "/portal" && req.method === "GET") {
    const role = url.searchParams.get("role") || "marshal";
    const eventId = url.searchParams.get("eventId") || EVENT_ID;
    const token = url.searchParams.get("token") || "";

    const portalTitle: Record<string, string> = {
      scanner: "Check-in Scanner",
      marshal: "Marshal Console",
      announcer: "Announcer Board",
      deck_captain: "Deck Captain",
      judge: "Judge Panel",
      chairman: "Chairman Console",
      dj: "DJ Console",
      scrutineer: "Scrutineer Console",
      videographer: "Videographer View",
      event_admin: "Admin Console",
    };
    const title = portalTitle[role] || "Staff Portal";

    // Fix #19: JSON-encode token to prevent XSS via crafted token strings
    const safeToken = JSON.stringify(token);
    const safeEventId = JSON.stringify(eventId);
    const safeRole = JSON.stringify(role);

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — ${escapeHtml(title)}</title>
<style>
*{box-sizing:border-box;margin:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column}
.topbar{background:#1e293b;padding:.75rem 1rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #334155;position:sticky;top:0;z-index:10}
.topbar-left{display:flex;align-items:center;gap:.5rem}
.topbar .staff-avatar{width:28px;height:28px;border-radius:50%;background:#6366f130;color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.65rem;flex-shrink:0}
.topbar h1{font-size:.95rem;color:#fff}
.topbar .badge{background:#22c55e20;color:#4ade80;font-size:.65rem;padding:2px 8px;border-radius:99px;font-weight:600}
.topbar-right{display:flex;align-items:center;gap:.75rem}
.conn-indicator{display:flex;align-items:center;gap:4px;font-size:.7rem;color:#94a3b8}
.conn-dot{width:8px;height:8px;border-radius:50%;transition:background .3s}
.conn-dot.connected{background:#22c55e;box-shadow:0 0 6px #22c55e60}
.conn-dot.reconnecting{background:#f59e0b;animation:pulse 1s infinite}
.conn-dot.disconnected{background:#ef4444}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.topbar .sync-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block}
.upgrade-banner{background:#1e293b;border-bottom:1px solid #334155;padding:.5rem 1rem;font-size:.75rem;color:#94a3b8;text-align:center}
.upgrade-banner a{color:#818cf8}
.container{max-width:600px;margin:0 auto;padding:1rem;flex:1}
.search-bar{width:100%;padding:.7rem;border-radius:8px;border:2px solid #334155;background:#1e293b;color:#fff;font-size:.9rem;outline:none;margin-bottom:1rem}
.search-bar:focus{border-color:#6366f1}
.list-item{background:#1e293b;border-radius:10px;padding:.85rem 1rem;margin-bottom:.5rem;display:flex;align-items:center;justify-content:space-between;border:1px solid #334155;transition:border-color .15s}
.list-item:hover{border-color:#475569}
.list-item .info{flex:1;min-width:0}
.list-item .name{font-weight:600;font-size:.9rem;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.list-item .detail{font-size:.75rem;color:#94a3b8;margin-top:2px}
.list-item .num{background:#6366f120;color:#a5b4fc;font-weight:700;font-size:.85rem;padding:4px 10px;border-radius:6px;margin-right:.75rem;min-width:2rem;text-align:center}
.btn{padding:.5rem 1rem;border-radius:8px;border:none;font-size:.8rem;font-weight:600;cursor:pointer;transition:all .15s}
.btn-check{background:#22c55e;color:#fff}.btn-check:hover{background:#16a34a}
.btn-checked{background:#334155;color:#4ade80;cursor:default}
.btn-deck{background:#f59e0b;color:#000}.btn-deck:hover{background:#d97706}
.btn-floor{background:#6366f1;color:#fff}.btn-floor:hover{background:#4f46e5}
.btn-done{background:#334155;color:#94a3b8;cursor:default}
.heat-header{background:#1e293b;border-radius:10px;padding:1rem;margin-bottom:.75rem;border:1px solid #334155}
.heat-header .heat-title{font-size:1.1rem;font-weight:700;color:#fff}
.heat-header .heat-sub{font-size:.8rem;color:#94a3b8;margin-top:4px}
.heat-status{display:inline-block;padding:2px 10px;border-radius:99px;font-size:.7rem;font-weight:600;margin-left:.5rem}
.heat-status.on_floor{background:#6366f120;color:#a5b4fc}
.heat-status.on_deck{background:#f59e0b20;color:#fbbf24}
.heat-status.scheduled{background:#33415520;color:#94a3b8}
.heat-status.completed{background:#22c55e20;color:#4ade80}
.empty{text-align:center;padding:3rem 1rem;color:#64748b;font-size:.9rem}
.tabs{display:flex;gap:2px;margin-bottom:1rem;background:#0f172a;border-radius:8px;padding:3px;border:1px solid #334155}
.tab{flex:1;padding:.5rem;text-align:center;border-radius:6px;font-size:.8rem;cursor:pointer;color:#94a3b8;font-weight:500;transition:all .15s}
.tab.active{background:#334155;color:#fff}
.refresh-btn{background:none;border:1px solid #334155;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:.7rem;cursor:pointer}
.refresh-btn:hover{background:#1e293b;color:#e2e8f0}
.count-badge{background:#6366f120;color:#a5b4fc;font-size:.7rem;padding:2px 8px;border-radius:99px;margin-left:.5rem}
#loading{text-align:center;padding:3rem;color:#64748b}
#loading .spinner{display:inline-block;width:24px;height:24px;border:3px solid #334155;border-top:3px solid #6366f1;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
/* Connection footer */
.conn-footer{background:#1e293b;border-top:1px solid #334155;padding:.5rem 1rem;display:flex;align-items:center;gap:.5rem;font-size:.7rem;color:#94a3b8;position:sticky;bottom:0}
.conn-footer .conn-dot{width:6px;height:6px}
</style></head>
<body>
<div class="topbar">
  <div class="topbar-left">
    <div class="staff-avatar" id="staff-initials">?</div>
    <div>
      <h1 id="staff-title">${escapeHtml(title)}</h1>
    </div>
    <span class="badge" id="role-badge">${escapeHtml(role)}</span>
  </div>
  <div class="topbar-right">
    <div class="conn-indicator">
      <span class="conn-dot connected" id="conn-dot"></span>
      <span id="latency-text"></span>
    </div>
    <button class="refresh-btn" onclick="loadData()">↻</button>
  </div>
</div>
<div class="upgrade-banner">Local-only mode — <a href="https://dance-flow-control.lovable.app" target="_blank">open full app</a> when internet is available</div>
<div class="container" id="portal-root">
  <div id="loading"><div class="spinner"></div><p style="margin-top:.75rem;font-size:.85rem">Loading event data…</p></div>
</div>
<div class="conn-footer">
  <span class="conn-dot connected" id="footer-dot"></span>
  <span id="footer-status">Connected</span>
  <span style="margin-left:auto" id="footer-sync"></span>
</div>
<script>
// Fix #2/#19: Token from URL → sessionStorage, strip from URL
(function(){
  const urlToken=${safeToken};
  if(urlToken){sessionStorage.setItem('eb_portal_token',urlToken);history.replaceState(null,'',location.pathname+'?role='+encodeURIComponent(${safeRole})+'&eventId='+encodeURIComponent(${safeEventId}));}
})();
const TOKEN=sessionStorage.getItem('eb_portal_token')||'';
const EVENT_ID=${safeEventId};
const ROLE=${safeRole};
const BASE=location.origin;
const AUTH={'authorization':'Bearer '+TOKEN,'content-type':'application/json'};

// --- Local op queue (survives WS disconnects and page reloads) ---
const OP_QUEUE_KEY='eb_pending_ops';
function getOpQueue(){try{return JSON.parse(localStorage.getItem(OP_QUEUE_KEY)||'[]')}catch{return[]}}
function saveOpQueue(q){localStorage.setItem(OP_QUEUE_KEY,JSON.stringify(q))}
function queueOp(op){const q=getOpQueue();q.push(op);saveOpQueue(q)}
async function drainOpQueue(){
  const q=getOpQueue();
  if(q.length===0)return;
  try{
    const r=await fetch(BASE+'/ops/batch',{method:'POST',headers:AUTH,body:JSON.stringify({ops:q})});
    if(r.ok){
      const d=await r.json();
      // Remove successfully applied ops
      const accepted=new Set((d.results||[]).filter(r=>r.accepted).map(r=>r.op_id));
      const remaining=q.filter(op=>!accepted.has(op.op_id));
      saveOpQueue(remaining);
    }
  }catch{/* will retry on next drain */}
}
// Drain on load and periodically
drainOpQueue();
setInterval(drainOpQueue,10000);

async function api(path,opts){
  const r=await fetch(BASE+path,{headers:AUTH,...opts});
  return r.json();
}

// Resilient op submit: try HTTP, fall back to queue
async function submitOp(op){
  try{
    const r=await fetch(BASE+'/ops/batch',{method:'POST',headers:AUTH,body:JSON.stringify({ops:[op]})});
    if(!r.ok)throw new Error('HTTP '+r.status);
    return await r.json();
  }catch{
    queueOp(op);
    return {ok:false,queued:true};
  }
}

// Fix #16: Debounce loadData — max once per second
let _loadPending=false;
let _loadTimer=null;
function debouncedLoad(){
  if(_loadPending)return;
  _loadPending=true;
  if(_loadTimer)clearTimeout(_loadTimer);
  _loadTimer=setTimeout(()=>{_loadPending=false;loadData();},1000);
}

// ===================== SCANNER PORTAL =====================
${role === "scanner" ? `
let credentials=[];
let checkins={};
let searchTerm='';

async function loadData(){
  try{
    const [ciRes, credRef]=await Promise.all([
      api('/state/checkins'),
      fetch(BASE+'/state/ref?table=credentials',{headers:AUTH}).then(r=>r.json()).catch(()=>null)
    ]);
    // Build lookup
    credentials=[];
    const ciMap={};
    (ciRes.checkins||[]).forEach(c=>ciMap[c.credential_id]=c.status);
    checkins=ciMap;
    // Try to get credentials from ref_data
    if(credRef?.data){
      credentials=typeof credRef.data==='string'?JSON.parse(credRef.data):credRef.data;
    }
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  const filtered=credentials.filter(c=>{
    if(!searchTerm)return true;
    const s=searchTerm.toLowerCase();
    return (c.person_name||'').toLowerCase().includes(s)||(c.competitor_number||'').toString().includes(s);
  });
  const checked=filtered.filter(c=>checkins[c.id]==='checked_in');
  const unchecked=filtered.filter(c=>checkins[c.id]!=='checked_in');
  let html='<input class="search-bar" placeholder="Search by name or number…" oninput="searchTerm=this.value;render()" value="'+esc(searchTerm)+'">';
  html+='<div class="tabs"><div class="tab '+(searchTerm?'':'active')+'" onclick="searchTerm=\\'\\';render()">All<span class="count-badge">'+credentials.length+'</span></div></div>';
  if(unchecked.length===0&&checked.length===0){
    html+='<div class="empty"><p style="font-size:1.1rem;margin-bottom:.75rem">📷 No credentials loaded yet</p><p style="color:#94a3b8;font-size:.8rem;line-height:1.6">The event organizer needs to sync credential data from the cloud app.<br>Once synced, attendees will appear here for check-in.</p><p style="color:#4ade80;font-size:.75rem;margin-top:.75rem">✓ You\\'re connected — data will appear automatically.</p></div>';
  }
  unchecked.forEach(c=>{
    html+='<div class="list-item"><div class="num">'+(c.competitor_number||'—')+'</div><div class="info"><div class="name">'+esc(c.person_name||'Unknown')+'</div><div class="detail">'+esc(c.credential_type||'competitor')+'</div></div><button class="btn btn-check" onclick="doCheckin(\\''+c.id+'\\')">Check In</button></div>';
  });
  checked.forEach(c=>{
    html+='<div class="list-item" style="opacity:.6"><div class="num">'+(c.competitor_number||'—')+'</div><div class="info"><div class="name">'+esc(c.person_name||'Unknown')+'</div><div class="detail">✅ Checked in</div></div><button class="btn btn-checked" disabled>Done</button></div>';
  });
  document.getElementById('portal-root').innerHTML=html;
}

async function doCheckin(credId){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'checkin',created_at_ms:Date.now(),payload:{credential_id:credId,status:'checked_in'}};
  await submitOp(op);
  checkins[credId]='checked_in';
  render();
}
` : ""}

// ===================== MARSHAL PORTAL =====================
${role === "marshal" || role === "deck_captain" || role === "floor_captain" ? `
let heats=[];
let heatStatuses={};
let marshalStatuses={};
let currentTab='active';

async function loadData(){
  try{
    const [hsRes,msRes]=await Promise.all([
      api('/state/heats'),
      api('/state/marshal')
    ]);
    heatStatuses={};
    (hsRes.heats||[]).forEach(h=>heatStatuses[h.heat_id]=h.status);
    marshalStatuses={};
    (msRes.marshal||[]).forEach(m=>marshalStatuses[m.heat_entry_id]=m.status);
    // Try to load heat ref data
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heats=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
      // Build from heat_status if no ref data
      heats=Object.keys(heatStatuses).map(id=>({id,heat_number:null,division_name:null}));
    }
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  const active=heats.filter(h=>{const s=heatStatuses[h.id];return !s||s==='scheduled'||s==='in_hole'||s==='on_deck'||s==='on_floor'});
  const done=heats.filter(h=>{const s=heatStatuses[h.id];return s==='completed'||s==='cancelled'});
  const list=currentTab==='active'?active:done;
  let html='<div class="tabs"><div class="tab '+(currentTab==='active'?'active':'')+'" onclick="currentTab=\\'active\\';render()">Active<span class="count-badge">'+active.length+'</span></div><div class="tab '+(currentTab==='done'?'active':'')+'" onclick="currentTab=\\'done\\';render()">Completed<span class="count-badge">'+done.length+'</span></div></div>';
  if(list.length===0){
    html+='<div class="empty"><p style="font-size:1.1rem;margin-bottom:.75rem">📋 No heats loaded yet</p><p style="color:#94a3b8;font-size:.8rem;line-height:1.6">The event organizer needs to sync schedule data from the cloud app.<br>Once synced, your heats will appear here automatically.</p><p style="color:#4ade80;font-size:.75rem;margin-top:.75rem">✓ You\\'re connected — you\\'ll be notified when heats arrive.</p></div>';
  }
  list.forEach(h=>{
    const status=heatStatuses[h.id]||'scheduled';
    const statusClass=status;
    html+='<div class="heat-header"><div class="heat-title">Heat '+(h.heat_number||'—')+' <span class="heat-status '+statusClass+'">'+status.replace('_',' ')+'</span></div><div class="heat-sub">'+(h.division_name||'')+'</div>';
    if(currentTab==='active'){
      html+='<div style="margin-top:.75rem;display:flex;gap:.5rem;flex-wrap:wrap">';
      if(status==='scheduled'||status==='in_hole')html+='<button class="btn btn-deck" onclick="setHeatState(\\''+h.id+'\\',\\'on_deck\\')">→ On Deck</button>';
      if(status==='on_deck')html+='<button class="btn btn-floor" onclick="setHeatState(\\''+h.id+'\\',\\'on_floor\\')">→ On Floor</button>';
      if(status==='on_floor')html+='<button class="btn btn-check" onclick="setHeatState(\\''+h.id+'\\',\\'completed\\')">✓ Complete</button>';
      html+='</div>';
    }
    html+='</div>';
  });
  document.getElementById('portal-root').innerHTML=html;
}

async function setHeatState(heatId,newStatus){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'heat_state',created_at_ms:Date.now(),payload:{heat_id:heatId,status:newStatus}};
  await submitOp(op);
  heatStatuses[heatId]=newStatus;
  render();
}
` : ""}

// ===================== ANNOUNCER PORTAL =====================
${role === "announcer" || role === "dj" ? `
let nowPlaying=null;
let heatsData=[];
let heatStatuses={};

async function loadData(){
  try{
    const [npRes,hsRes]=await Promise.all([
      api('/state/nowplaying'),
      api('/state/heats')
    ]);
    nowPlaying=npRes.now_playing;
    heatStatuses={};
    (hsRes.heats||[]).forEach(h=>heatStatuses[h.heat_id]=h.status);
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heatsData=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
      heatsData=Object.keys(heatStatuses).map(id=>({id,heat_number:null,division_name:null}));
    }
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  let html='';
  if(nowPlaying){
    html+='<div class="heat-header" style="border-color:#6366f1"><div class="heat-title">🎵 Now: Heat '+(nowPlaying.heat_number||'—')+' <span class="heat-status on_floor">'+(nowPlaying.status||'playing')+'</span></div><div class="heat-sub">'+(nowPlaying.division_name||'')+' — '+(nowPlaying.dance_code||'')+'</div></div>';
  }else{
    html+='<div class="heat-header"><div class="heat-title" style="color:#94a3b8">No heat currently playing</div></div>';
  }
  html+='<h3 style="font-size:.85rem;color:#94a3b8;margin:1rem 0 .5rem">Schedule</h3>';
  const upcoming=heatsData.filter(h=>{const s=heatStatuses[h.id];return !s||s==='scheduled'||s==='in_hole'||s==='on_deck'||s==='on_floor'});
  if(upcoming.length===0){
    html+='<div class="empty">No upcoming heats</div>';
  }
  upcoming.forEach(h=>{
    const status=heatStatuses[h.id]||'scheduled';
    html+='<div class="list-item"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat '+h.id.slice(0,6))+'</div><div class="detail"><span class="heat-status '+status+'">'+status.replace('_',' ')+'</span></div></div></div>';
  });
  document.getElementById('portal-root').innerHTML=html;
}
` : ""}

// ===================== GENERIC FALLBACK =====================
${!["scanner","marshal","deck_captain","floor_captain","announcer","dj"].includes(role) ? `
async function loadData(){
  document.getElementById('portal-root').innerHTML='<div class="empty"><p style="font-size:1.1rem;margin-bottom:.5rem">📋 ${title}</p><p>This role\\'s full features are available in the <a href="https://dance-flow-control.lovable.app" style="color:#818cf8">full app</a>.</p><p style="margin-top:1rem">Basic event status:</p><div id="status-info" style="margin-top:.75rem">Loading…</div></div>';
  try{
    const [npRes,hsRes]=await Promise.all([api('/state/nowplaying'),api('/state/heats')]);
    let info='';
    if(npRes.now_playing){
      info+='<p>🎵 Now playing: Heat '+(npRes.now_playing.heat_number||'—')+'</p>';
    }
    const total=(hsRes.heats||[]).length;
    const completed=(hsRes.heats||[]).filter(h=>h.status==='completed').length;
    info+='<p>Heats: '+completed+'/'+total+' completed</p>';
    document.getElementById('status-info').innerHTML=info;
  }catch(e){
    document.getElementById('status-info').innerHTML='<p style="color:#f87171">Could not load status</p>';
  }
}
` : ""}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

// Populate topbar with staff name from localStorage
(function(){
  try{
    const sess=JSON.parse(localStorage.getItem('eventbox_staff_session')||'{}');
    if(sess.staff_name){
      const initials=sess.staff_name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
      document.getElementById('staff-initials').textContent=initials;
      document.getElementById('staff-title').textContent=sess.staff_name;
    }
  }catch{}
})();

// Auto-refresh every 10 seconds
loadData();
setInterval(loadData,10000);

// Connection health tracking
let lastPongAt=0;
let wsState='disconnected';
function updateConnUI(){
  const dot=document.getElementById('conn-dot');
  const footerDot=document.getElementById('footer-dot');
  const footerStatus=document.getElementById('footer-status');
  const latencyText=document.getElementById('latency-text');
  const classes={connected:'connected',reconnecting:'reconnecting',disconnected:'disconnected'};
  [dot,footerDot].forEach(el=>{el.className='conn-dot '+classes[wsState]});
  if(wsState==='connected'){
    footerStatus.textContent='Connected';
    if(lastPongAt){
      const ago=Math.floor((Date.now()-lastPongAt)/1000);
      document.getElementById('footer-sync').textContent='Last sync: '+ago+'s ago';
    }
  }else if(wsState==='reconnecting'){
    footerStatus.textContent='Reconnecting…';
    latencyText.textContent='';
  }else{
    footerStatus.textContent='Disconnected';
    latencyText.textContent='';
  }
}
setInterval(updateConnUI,2000);

// Fix #5/#8: WebSocket with exponential backoff reconnect + debounced loadData + health tracking
(function(){
  if(!TOKEN)return;
  let backoff=1000;
  const maxBackoff=30000;
  let pingInterval=null;
  function connect(){
    try{
      wsState='reconnecting';updateConnUI();
      const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//' +location.host+'/ws?token='+TOKEN);
      ws.onopen=function(){
        backoff=1000;wsState='connected';updateConnUI();
        drainOpQueue(); // Flush queued ops on reconnect
        // Start ping every 5s
        if(pingInterval)clearInterval(pingInterval);
        pingInterval=setInterval(()=>{
          if(ws.readyState===1)ws.send(JSON.stringify({type:'ping',t:Date.now()}));
        },5000);
      };
      ws.onmessage=function(e){
        try{
          const m=JSON.parse(e.data);
          if(m.type==='pong'){
            lastPongAt=Date.now();
            const latency=m.time?(Date.now()-m.time):0;
            document.getElementById('latency-text').textContent=latency+'ms';
          }
          if(m.type==='op.applied')debouncedLoad();
        }catch{}
      };
      ws.onclose=function(){
        wsState='disconnected';updateConnUI();
        if(pingInterval){clearInterval(pingInterval);pingInterval=null}
        setTimeout(()=>{connect();backoff=Math.min(backoff*2,maxBackoff);},backoff);
      };
    }catch{
      wsState='disconnected';updateConnUI();
      setTimeout(()=>{connect();backoff=Math.min(backoff*2,maxBackoff);},backoff);
    }
  }
  connect();
})();
</script></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // /state/ref is now handled inside the /state/* switch block above

  // ---- /app/* catch-all: redirect to local portal or cloud ----
  if (url.pathname.startsWith("/app/")) {
    // Map /app/* paths to roles for local portal
    const appRoleMap: Record<string, string> = {
      "/app/checkin": "scanner",
      "/app/marshal": "marshal",
      "/app/announcer": "announcer",
      "/app/judge": "judge",
      "/app/chairman": "chairman",
      "/app/dj": "dj",
      "/app/videographer": "videographer",
      "/app/deckcaptain": "deck_captain",
      "/app/scrutineer": "scrutineer",
      "/app/events": "event_admin",
    };
    const role = appRoleMap[url.pathname] || "marshal";
    const eventId = url.searchParams.get("eventId") || EVENT_ID;
    const localUrl = `${url.origin}/portal?role=${encodeURIComponent(role)}&eventId=${encodeURIComponent(eventId)}`;
    const pwaBase = "https://dance-flow-control.lovable.app";
    const pwaUrl = pwaBase + url.pathname + url.search + (url.search ? "&" : "?") + "eventbox=" + encodeURIComponent(url.origin);
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Staff Portal</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);text-align:center}
h1{margin:0 0 .5rem;font-size:1.5rem;color:#fff}
p{color:#94a3b8;font-size:.85rem;line-height:1.6}
a.btn{display:inline-block;padding:.7rem 1.5rem;border-radius:8px;text-decoration:none;font-weight:600;font-size:.9rem;margin:.5rem}
a.local{background:#6366f1;color:#fff}a.local:hover{background:#4f46e5}
a.cloud{background:#334155;color:#e2e8f0}a.cloud:hover{background:#475569}
</style></head>
<body><div class="card">
<h1>Staff Portal</h1>
<p>Choose how to connect:</p>
<div style="margin-top:1rem">
<a class="btn local" href="${escapeHtml(localUrl)}">Open Local Portal</a><br>
<a class="btn cloud" href="${escapeHtml(pwaUrl)}">Open Full App (needs internet)</a>
</div>
<p style="margin-top:1.5rem;font-size:.75rem">The local portal works on this network without internet. The full app has more features but requires internet access on first load.</p>
</div></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  return json({ error: "not found" }, 404);
});

console.log(`\n🎯 EventBox v0.4 running on port ${PORT}`);
console.log(`   Event:     ${EVENT_ID}`);
console.log(`   Room code: ${ROOM_CODE}`);
console.log(`   Database:  ${DB_PATH}`);
console.log(`   Admin key: ${ADMIN_SECRET === ROOM_CODE ? "(same as room code)" : "(custom EVENTBOX_ADMIN_SECRET)"}`);
console.log(`   Auth:      HMAC-SHA256 tokens (${TOKEN_TTL_MS / 3600000}h TTL)\n`);
