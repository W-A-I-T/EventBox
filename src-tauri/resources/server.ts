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
let ADMIN_SECRET =
  Deno.env.get("EVENTBOX_ADMIN_SECRET") ??
  ROOM_CODE;
const EVENT_ID = Deno.env.get("EVENTBOX_EVENT_ID") ?? "";
const CHASSEFLOW_API = Deno.env.get("EVENTBOX_CHASSEFLOW_API") ?? "https://dance-flow-control.lovable.app";
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

CREATE TABLE IF NOT EXISTS payments (
  event_id         TEXT NOT NULL,
  credential_id    TEXT NOT NULL,
  amount_cents     INTEGER,
  currency         TEXT DEFAULT 'USD',
  payment_method   TEXT,
  terminal_id      TEXT,
  external_ref     TEXT,
  status           TEXT NOT NULL,
  confirmed_by     TEXT,
  confirmed_at_ms  INTEGER NOT NULL,
  PRIMARY KEY(event_id, credential_id)
);

CREATE TABLE IF NOT EXISTS ref_data (
  event_id       TEXT NOT NULL,
  table_name     TEXT NOT NULL,
  data_json      TEXT NOT NULL,
  fetched_at     TEXT NOT NULL,
  PRIMARY KEY(event_id, table_name)
);

-- Staff sessions for BYOD portal
-- Fix #3: Timestamps stored as TEXT to avoid @db/sqlite@0.12 32-bit integer overflow
CREATE TABLE IF NOT EXISTS staff_sessions (
  id             TEXT PRIMARY KEY,
  event_id       TEXT NOT NULL,
  role           TEXT NOT NULL,
  staff_name     TEXT NOT NULL,
  join_code      TEXT NOT NULL UNIQUE,
  device_id      TEXT,
  created_at     TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  revoked_at     TEXT
);

-- Server config persistence (room code, etc.)
CREATE TABLE IF NOT EXISTS server_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

// Migrate staff_sessions timestamps from INTEGER to TEXT
// (fixes @db/sqlite@0.12 32-bit integer overflow on millisecond timestamps)
try {
  const cols = queryRows(`PRAGMA table_info(staff_sessions)`, []);
  const expiresCol = cols.find((c) => c[1] === "expires_at");
  if (expiresCol && String(expiresCol[2]).toUpperCase() === "INTEGER") {
    console.log("[EventBox] Migrating staff_sessions timestamps to TEXT...");
    db.exec(`BEGIN TRANSACTION;`);
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS staff_sessions_new (
          id TEXT PRIMARY KEY, event_id TEXT NOT NULL, role TEXT NOT NULL,
          staff_name TEXT NOT NULL, join_code TEXT NOT NULL UNIQUE,
          device_id TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
        );
        INSERT INTO staff_sessions_new SELECT
          id, event_id, role, staff_name, join_code, device_id,
          CAST(created_at AS TEXT), CAST(expires_at AS TEXT),
          CASE WHEN revoked_at IS NOT NULL THEN CAST(revoked_at AS TEXT) ELSE NULL END
        FROM staff_sessions;
        DROP TABLE staff_sessions;
        ALTER TABLE staff_sessions_new RENAME TO staff_sessions;
      `);
      db.exec(`COMMIT;`);
    } catch (migrationErr) {
      db.exec(`ROLLBACK;`);
      throw migrationErr;
    }
    console.log("[EventBox] Migration complete");
  }
} catch (e) {
  console.error("[EventBox] Migration check error (non-fatal):", e);
}

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
// Re-sync ADMIN_SECRET after room code restoration (avoid stale value lockout)
if (!Deno.env.get("EVENTBOX_ADMIN_SECRET")) { ADMIN_SECRET = ROOM_CODE; }

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
  scanner: ["checkin", "payment_confirmed"],
  judge: ["score", "score_submission"],
  marshal: ["marshal", "scratch", "heat_state"],
  deck_captain: ["marshal", "heat_state"],
  floor_captain: ["marshal", "heat_state", "scratch"],
  scrutineer: ["result_publish"],
  announcer: ["nowplaying"],
  dj: ["nowplaying"],
  chairman: ["chairman_override", "heat_state", "marshal", "scratch", "nowplaying", "payment_confirmed"],
  videographer: [],
  event_admin: [
    "checkin", "score", "score_submission", "marshal", "heat_state",
    "scratch", "nowplaying", "result_publish", "chairman_override", "payment_confirmed",
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
  | { accepted: false; reason: "duplicate" | "fsm_rejected" | "invalid" | "wrong_event" | "unauthorized"; detail?: Record<string, unknown> };

// ---------------------------------------------------------------------------
// WebSocket management
// ---------------------------------------------------------------------------
const wsClientsByEvent = new Map<string, Set<WebSocket>>();
// Track device_id per WebSocket for presence detection
const wsDeviceMap = new Map<WebSocket, string>();

function getConnectedDeviceIds(): Set<string> {
  const ids = new Set<string>();
  const set = wsClientsByEvent.get(EVENT_ID);
  if (!set) return ids;
  for (const ws of set) {
    if (ws.readyState === WebSocket.OPEN) {
      const did = wsDeviceMap.get(ws);
      if (did) ids.add(did);
    }
  }
  return ids;
}

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
          `SELECT status, updated_by FROM marshal_status WHERE event_id=? AND heat_entry_id=?`,
          [op.event_id, p.heat_entry_id],
        );
        const currentState = rows.length > 0 ? String(rows[0][0]) : null;
        const currentUpdatedBy = rows.length > 0 ? String(rows[0][1] ?? "") : "";

        if (!isFsmAllowed(currentState, p.status as string)) {
          db.exec("ROLLBACK");
          return { accepted: false, reason: "fsm_rejected", detail: { current_status: currentState, updated_by: currentUpdatedBy } };
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
          `SELECT status, updated_by FROM heat_status WHERE event_id=? AND heat_id=?`,
          [op.event_id, p.heat_id],
        );
        const currentState = rows.length > 0 ? String(rows[0][0]) : null;
        const currentUpdatedBy = rows.length > 0 ? String(rows[0][1] ?? "") : "";

        if (!isFsmAllowed(currentState, p.status as string)) {
          db.exec("ROLLBACK");
          return { accepted: false, reason: "fsm_rejected", detail: { current_status: currentState, updated_by: currentUpdatedBy } };
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

    case "payment_confirmed": {
      if (p?.credential_id && p?.status) {
        queryRun(
          `INSERT INTO payments(event_id, credential_id, amount_cents, currency, payment_method, terminal_id, external_ref, status, confirmed_by, confirmed_at_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(event_id, credential_id) DO UPDATE SET
             amount_cents=excluded.amount_cents, currency=excluded.currency,
             payment_method=excluded.payment_method, terminal_id=excluded.terminal_id,
             external_ref=excluded.external_ref, status=excluded.status,
             confirmed_by=excluded.confirmed_by, confirmed_at_ms=excluded.confirmed_at_ms`,
          [
            op.event_id,
            p.credential_id,
            p.amount_cents ?? null,
            p.currency ?? "USD",
            p.payment_method ?? null,
            p.terminal_id ?? null,
            p.external_ref ?? null,
            p.status,
            op.actor_device_id ?? null,
            now,
          ],
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
// Embedded templates (for deno compile — copy from templates/*.html)
// ---------------------------------------------------------------------------
// To update: edit templates/*.html then copy contents here.

const EMBEDDED_DASHBOARD = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{EVENT_NAME}} — EventBox</title>
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
.sync-bar{display:flex;align-items:center;gap:.5rem;padding:.65rem .85rem;background:#1e293b;border-radius:10px;margin-bottom:1rem;font-size:.8rem}
.sync-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sync-dot.ok{background:#22c55e;box-shadow:0 0 6px #22c55e60}
.sync-dot.none{background:#f59e0b}
.sync-info{flex:1;color:#94a3b8}
.sync-info strong{color:#e2e8f0}
.sync-btn{background:none;border:1px solid #334155;color:#94a3b8;padding:3px 10px;border-radius:6px;font-size:.7rem;cursor:pointer}
.sync-btn:hover{background:#334155;color:#e2e8f0}
.roster-item{display:flex;align-items:center;gap:.65rem;padding:.5rem 0;border-bottom:1px solid #1a2744;font-size:.8rem}
.roster-item:last-child{border-bottom:none}
.avatar{width:30px;height:30px;border-radius:50%;background:#6366f130;color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.7rem;flex-shrink:0}
.roster-name{color:#fff;font-weight:500}
.role-badge{display:inline-block;background:#22c55e20;color:#4ade80;padding:1px 8px;border-radius:99px;font-size:.65rem;font-weight:600;margin-left:.35rem}
.presence-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;flex-shrink:0;margin-left:auto}
.presence-dot.offline{background:#64748b}
.no-sessions{color:#64748b;font-size:.8rem;padding:.75rem 0}
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
.auth-overlay{position:fixed;inset:0;background:#0f172aee;display:flex;align-items:center;justify-content:center;z-index:50}
.auth-card{background:#1e293b;border-radius:16px;padding:2rem;max-width:360px;width:90%}
.auth-card h2{font-size:1.1rem;color:#fff;margin-bottom:.5rem}
.auth-card p{font-size:.8rem;color:#94a3b8;margin-bottom:1rem}
.auth-card .row{display:flex;gap:.5rem}
.auth-card input{flex:1;padding:.6rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff;font-size:.85rem;outline:none}
.auth-card input:focus{border-color:#6366f1}
.auth-error{color:#f87171;font-size:.8rem;margin-top:.5rem}
.skeleton{background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:8px;height:2rem;margin:.5rem 0}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
</style></head>
<body>

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
    <h1>{{EVENT_NAME}}</h1>
    <div class="event-sub">EventBox v0.4 · up {{UPTIME}}</div>
  </div>
  <div style="text-align:right">
    <span class="live-badge">● Live</span>
    <div class="online-count" id="online-count">{{DEVICES}} online</div>
  </div>
</header>

<div class="sync-bar">
  <span class="sync-dot {{SYNC_DOT_CLASS}}" id="sync-dot"></span>
  <span class="sync-info" id="sync-info"><strong>{{HEATS}} heats</strong> synced · last sync {{LAST_SYNC}}</span>
  <button class="sync-btn" id="cloud-sync-btn" onclick="syncFromCloud()">☁ Sync from cloud</button>
  <button class="sync-btn" onclick="refreshSync()">↻ Refresh stats</button>
</div>

<div class="section" id="roster-section">
  <div class="section-title"><span class="icon">👥</span> Staff on floor</div>
  <div id="roster-list">
    <div class="skeleton"></div><div class="skeleton" style="width:80%"></div>
  </div>
</div>

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
  <div class="fallback-code">Or share room code: <strong>{{ROOM_CODE}}</strong></div>
  <div style="margin-top:.75rem;border-top:1px solid #334155;padding-top:.75rem">
    <div class="section-title" style="margin-bottom:.5rem"><span class="icon">📦</span> Import Event Data</div>
    <p style="font-size:.75rem;color:#64748b;margin-bottom:.5rem">Load a JSON file exported from ChasséFlow (for venues with no internet)</p>
    <input type="file" id="import-file" accept=".json" style="display:none" onchange="importFile(this)">
    <button class="btn btn-primary" style="font-size:.75rem;padding:.4rem .8rem" onclick="document.getElementById('import-file').click()">📂 Import from file</button>
    <span id="import-status" style="font-size:.75rem;color:#94a3b8;margin-left:.5rem"></span>
  </div>
</div>

<div class="section">
  <div class="section-title"><span class="icon">📊</span> Server Status</div>
  <div class="stat-grid">
    <div class="stat"><div class="num">{{DEVICES}}</div><div class="lbl">Connected</div></div>
    <div class="stat"><div class="num">{{HEATS}}</div><div class="lbl">Heats</div></div>
    <div class="stat"><div class="num">{{OPS}}</div><div class="lbl">Ops</div></div>
    <div class="stat"><div class="num">{{UPTIME}}</div><div class="lbl">Uptime</div></div>
  </div>
  <details>
    <summary>Technical details</summary>
    <div class="tech-grid">
      Event ID: <span class="val" style="cursor:pointer" onclick="navigator.clipboard.writeText({{JSON_EVENT_ID}}).then(()=>showToast('Copied!'))">{{EVENT_ID_RAW}}</span><br>
      Port: <span class="val">{{PORT}}</span><br>
      Database: <span class="val">{{DB_PATH}}</span><br>
      Version: <span class="val">0.4.0</span>
    </div>
  </details>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
let adminToken=sessionStorage.getItem('eventbox_admin_token')||'';
const ROOM_CODE={{JSON_ROOM_CODE}};
const autoAuth={{AUTO_AUTH}};

function showToast(m){const t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

async function doAutoAuth(){
  const did=localStorage.getItem('device_id')||crypto.randomUUID();
  localStorage.setItem('device_id',did);
  try{
    const r=await fetch('/auth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({device_id:did,admin_secret:ROOM_CODE})});
    const d=await r.json();
    if(r.ok){adminToken=d.token;sessionStorage.setItem('eventbox_admin_token',adminToken);localStorage.setItem('eventbox_room_code',ROOM_CODE);return true}
  }catch{}
  return false;
}

async function handleAuth(){
  if(adminToken){
    try{
      const r=await fetch('/api/staff-sessions',{headers:{'authorization':'Bearer '+adminToken}});
      if(r.ok){loadRoster(await r.json());return}
    }catch{}
    adminToken='';sessionStorage.removeItem('eventbox_admin_token');
  }
  if(autoAuth){
    const ok=await doAutoAuth();
    if(ok){loadRoster();return}
  }
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
    adminToken=d.token;sessionStorage.setItem('eventbox_admin_token',adminToken);localStorage.setItem('eventbox_room_code',ROOM_CODE);
    document.getElementById('auth-overlay').classList.add('hidden');
    loadRoster();
  }catch(e){
    const el=document.getElementById('auth-error');
    el.classList.remove('hidden');el.textContent=e.message;
  }
}
document.getElementById('admin-pwd')?.addEventListener('keydown',e=>{if(e.key==='Enter')authAdmin()});

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
      const dotClass=s.online?'presence-dot':'presence-dot offline';
      return '<div class="roster-item"><div class="avatar">'+esc(initials)+'</div><div><span class="roster-name">'+esc(s.staff_name)+'</span><span class="role-badge">'+esc(s.role)+'</span></div><span class="'+dotClass+'"></span><button class="btn btn-danger" style="margin-left:.5rem" onclick="revoke(\\''+s.id+'\\')">Revoke</button></div>';
    }).join('');
  }catch(e){
    document.getElementById('roster-list').innerHTML='<div class="no-sessions" style="color:#f87171">'+esc(e.message)+'</div>';
  }
}

setInterval(()=>{if(adminToken)loadRoster()},5000);

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
    const tokenUrl=location.origin+'/staff/join?token='+encodeURIComponent(d.join_code);
    const container=document.getElementById('generated-code');
    container.classList.remove('hidden');
    container.innerHTML='<div class="generated-qr" id="gen-qr"></div><div style="text-align:center;margin-top:.5rem;font-size:.75rem;color:#94a3b8">'+esc(d.staff_name)+' · '+esc(d.role)+'<br><span style="font-family:monospace;color:#38bdf8;cursor:pointer" onclick="navigator.clipboard.writeText(\\''+tokenUrl+'\\').then(()=>showToast(\\'Link copied!\\'))">'+esc(tokenUrl)+'</span></div>';
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

async function importFile(input){
  const file=input.files[0];
  if(!file)return;
  const status=document.getElementById('import-status');
  status.textContent='Importing…';status.style.color='#94a3b8';
  try{
    const text=await file.text();
    const data=JSON.parse(text);
    if(!data.tables||!Array.isArray(data.tables))throw new Error('Invalid format — expected { tables: [...] }');
    if(data.event_id && data.event_id!=={{JSON_EVENT_ID}}){
      if(!confirm('This file is for a different event ('+data.event_id.slice(0,8)+'…). This server is running event '+{{JSON_EVENT_ID}}.slice(0,8)+'…. Import anyway?')){
        status.textContent='Import cancelled';status.style.color='#94a3b8';input.value='';return;
      }
    }
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

async function refreshSync(){
  showToast('Refreshing local stats…');
  setTimeout(()=>location.reload(),500);
}

async function syncFromCloud(){
  const btn=document.getElementById('cloud-sync-btn');
  const info=document.getElementById('sync-info');
  const dot=document.getElementById('sync-dot');
  btn.disabled=true;btn.textContent='Syncing…';
  info.innerHTML='<strong>Pulling from ChasseFlow…</strong>';
  dot.className='sync-dot none';
  try{
    const r=await fetch('/api/sync-from-cloud',{method:'POST',headers:{'content-type':'application/json','authorization':'Bearer '+adminToken}});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Sync failed');
    info.innerHTML='<strong>'+d.synced+' tables synced</strong> &middot; just now';
    dot.className='sync-dot ok';
    showToast('Synced '+d.synced+' tables from cloud!');
    setTimeout(()=>location.reload(),2000);
  }catch(e){
    info.innerHTML='<strong style="color:#f87171">Sync failed:</strong> '+esc(e.message);
    dot.className='sync-dot none';
    showToast('Sync failed: '+e.message);
  }finally{
    btn.disabled=false;btn.textContent='\\u2601 Sync from cloud';
  }
}

function drawQR(url,containerId){
  const qr=qrcode(0,'L');qr.addData(url);qr.make();
  document.getElementById(containerId).innerHTML=qr.createImgTag(4,6);
}

handleAuth();
</script>
</body></html>
`;

const EMBEDDED_JOIN = `<!DOCTYPE html>
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
.welcome{text-align:center}
.welcome .avatar-lg{width:64px;height:64px;border-radius:50%;background:#6366f130;color:#a5b4fc;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:1.5rem;margin:0 auto 1rem}
.welcome h2{color:#fff;font-size:1.2rem;margin-bottom:.25rem}
.welcome .event-name{color:#94a3b8;font-size:.8rem;margin-bottom:1rem}
.spinner{display:inline-block;width:20px;height:20px;border:3px solid #334155;border-top:3px solid #6366f1;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style></head>
<body><div class="card">

<div id="token-loading" class="hidden" style="text-align:center;padding:2rem 0">
  <div class="spinner"></div>
  <p style="margin-top:1rem;color:#94a3b8;font-size:.85rem">Connecting…</p>
</div>

<div id="token-welcome" class="hidden">
  <div class="welcome">
    <div class="avatar-lg" id="welcome-avatar">?</div>
    <h2 id="welcome-name">Welcome!</h2>
    <div><span class="role-badge" id="welcome-role"></span></div>
    <div class="event-name">{{EVENT_NAME}}</div>
    <button class="primary" id="welcome-btn" onclick="openPortal()">Open console →</button>
  </div>
</div>

<div id="step1" class="hidden">
  <h1>Join Staff Portal</h1>
  <p class="subtitle">Connect to EventBox on this network</p>
  <div class="steps"><div class="step active" id="s1"></div><div class="step" id="s2"></div></div>
  <label>Room Code</label>
  <input class="code-input" id="code" placeholder="000000" maxlength="8" value="{{JOIN_CODE}}" autofocus>
  <button class="primary" id="btn1" onclick="validateCode()">Continue →</button>
</div>

<div id="step2" class="hidden">
  <h1>Join Staff Portal</h1>
  <p class="subtitle">{{EVENT_NAME}}</p>
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

const tokenParam={{JSON_TOKEN_PARAM}};
const joinParam={{JSON_JOIN_CODE}};

if(tokenParam){
  document.getElementById('token-loading').classList.remove('hidden');
  tokenJoin(tokenParam);
}else{
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
    const did=localStorage.getItem('device_id')||crypto.randomUUID();
    localStorage.setItem('device_id',did);
    // Try joining directly — handles both universal room codes and per-staff join codes
    const r=await fetch('/api/staff-sessions/join',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({join_code:code,device_id:did})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error==='invalid_room_code'?'Invalid room code':d.error||'Failed');
    // Per-staff code: role already assigned, skip step 2 and go directly to portal
    if(d.token&&d.role){
      localStorage.setItem('eventbox_staff_session',JSON.stringify(d));
      localStorage.setItem('eventbox_base_url',location.origin);
      joinData=d;
      showMsg('success','');
      msg.innerHTML='✅ Welcome, <strong>'+esc(d.staff_name)+'</strong>! <span class="role-badge">'+esc(d.role)+'</span>';
      const localPortalUrl=location.origin+'/portal?role='+encodeURIComponent(d.role)+'&eventId='+d.event_id+'&token='+encodeURIComponent(d.token);
      setTimeout(()=>{location.href=localPortalUrl},1500);
      return;
    }
    // Universal room code: advance to step 2 for role selection
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

const EMBEDDED_PORTAL = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — {{TITLE}}</title>
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
.conn-footer{background:#1e293b;border-top:1px solid #334155;padding:.5rem 1rem;display:flex;align-items:center;gap:.5rem;font-size:.7rem;color:#94a3b8;position:sticky;bottom:0}
.conn-footer .conn-dot{width:6px;height:6px}
</style></head>
<body>
<div class="topbar">
  <div class="topbar-left">
    <div class="staff-avatar" id="staff-initials">?</div>
    <div>
      <h1 id="staff-title">{{TITLE}}</h1>
    </div>
    <span class="badge" id="role-badge">{{ROLE}}</span>
  </div>
  <div class="topbar-right">
    <div class="conn-indicator">
      <span class="conn-dot connected" id="conn-dot"></span>
      <span id="latency-text"></span>
    </div>
    <button class="refresh-btn" onclick="loadData()">↻</button>
  </div>
</div>
<div class="upgrade-banner" id="upgrade-banner" style="display:none">Local-only mode &mdash; <a href="https://dance-flow-control.lovable.app" target="_blank">open full app</a> for additional features</div>
<div class="container" id="portal-root">
  <div id="loading"><div class="spinner"></div><p style="margin-top:.75rem;font-size:.85rem">Loading event data…</p></div>
</div>
<div class="conn-footer">
  <span class="conn-dot connected" id="footer-dot"></span>
  <span id="footer-status">Connected</span>
  <span style="margin-left:auto" id="footer-sync"></span>
</div>
<script>
// Kiosk mode: bypass token auth, use localStorage session
const KIOSK_ID={{JSON_KIOSK_ID}};
if(KIOSK_ID){
  const ks=localStorage.getItem('kiosk_session_'+KIOSK_ID);
  if(ks){
    try{
      const sess=JSON.parse(ks);
      const initials=(sess.volunteer_name||'?').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
      document.getElementById('staff-initials').textContent=initials;
      document.getElementById('staff-title').textContent=sess.volunteer_name+' — '+(sess.role||'').replace(/_/g,' ');
      document.getElementById('role-badge').textContent='kiosk';
    }catch{}
  }
}
// Fix #2/#19: Token from URL → sessionStorage, strip from URL
(function(){
  const urlToken={{JSON_TOKEN}};
  if(urlToken){sessionStorage.setItem('eb_portal_token',urlToken);history.replaceState(null,'',location.pathname+'?role='+encodeURIComponent({{JSON_ROLE}})+'&eventId='+encodeURIComponent({{JSON_EVENT_ID}})+(KIOSK_ID?'&kiosk='+encodeURIComponent(KIOSK_ID):''));}
})();
let TOKEN=sessionStorage.getItem('eb_portal_token')||'';
const BASE=location.origin;
// Auto-recover session from localStorage if sessionStorage token is empty
if(!TOKEN&&!KIOSK_ID){(async function recoverSession(){
  const saved=localStorage.getItem('eventbox_staff_session');
  if(!saved)return;
  try{
    const sess=JSON.parse(saved);
    if(!sess.staff_session_id&&!sess.id)return;
    const sessionId=sess.staff_session_id||sess.id;
    const deviceId=localStorage.getItem('device_id')||'';
    const r=await fetch(BASE+'/auth/refresh',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({staff_session_id:sessionId,device_id:deviceId})});
    if(!r.ok){localStorage.removeItem('eventbox_staff_session');window.location.href='/staff/join';return}
    const d=await r.json();
    sessionStorage.setItem('eb_portal_token',d.token);
    TOKEN=d.token;
    window.location.reload();
  }catch{}
})()}
// For kiosk mode without token, still allow data loading
if(!TOKEN&&!KIOSK_ID&&!localStorage.getItem('eventbox_staff_session')){
  document.getElementById('portal-root').innerHTML='<div class="empty"><p>Session expired</p><a href="/staff/join" style="color:#818cf8">Rejoin</a></div>';
}
const EVENT_ID={{JSON_EVENT_ID}};
const ROLE={{JSON_ROLE}};
const AUTH={'authorization':'Bearer '+TOKEN,'content-type':'application/json'};

// --- Local op queue (survives WS disconnects and page reloads) ---
const OP_QUEUE_KEY='eb_pending_ops';
function getOpQueue(){try{return JSON.parse(localStorage.getItem(OP_QUEUE_KEY)||'[]')}catch{return[]}}
function saveOpQueue(q){localStorage.setItem(OP_QUEUE_KEY,JSON.stringify(q))}
function queueOp(op){
  const q=getOpQueue();
  if(q.some(o=>o.op_id===op.op_id))return;
  q.push(op);saveOpQueue(q);
}
const DRAIN_BATCH_SIZE=30;
async function drainOpQueue(){
  const q=getOpQueue();
  if(q.length===0)return;
  const batch=q.slice(0,DRAIN_BATCH_SIZE);
  try{
    const r=await fetch(BASE+'/ops/batch',{method:'POST',headers:AUTH,body:JSON.stringify({ops:batch})});
    if(r.ok){
      const d=await r.json();
      const accepted=new Set((d.results||[]).filter(r=>r.accepted||r.reason==='duplicate').map(r=>r.op_id));
      const remaining=q.filter(op=>!accepted.has(op.op_id));
      saveOpQueue(remaining);
      if(remaining.length>0)setTimeout(drainOpQueue,200);
    }
  }catch{}
}
drainOpQueue();
setInterval(drainOpQueue,10000);

async function api(path,opts){
  const r=await fetch(BASE+path,{headers:AUTH,...opts});
  return r.json();
}

function showQueuedToast(){
  const t=document.getElementById('toast');
  if(t){t.textContent='Saved offline — will sync when connected';t.style.display='block';setTimeout(()=>t.style.display='none',3000);}
}

async function submitOp(op){
  try{
    const r=await fetch(BASE+'/ops/batch',{method:'POST',headers:AUTH,body:JSON.stringify({ops:[op]})});
    if(!r.ok)throw new Error('HTTP '+r.status);
    return await r.json();
  }catch{
    queueOp(op);
    showQueuedToast();
    return {ok:false,queued:true};
  }
}

let _loadPending=false;
let _loadTimer=null;
function debouncedLoad(){
  if(_loadPending)return;
  _loadPending=true;
  if(_loadTimer)clearTimeout(_loadTimer);
  _loadTimer=setTimeout(()=>{_loadPending=false;loadData();},1000);
}

{{ROLE_SCRIPT}}

function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

function portalToast(msg){
  let t=document.getElementById('portal-toast');
  if(!t){t=document.createElement('div');t.id='portal-toast';t.style.cssText='position:fixed;bottom:4rem;left:50%;transform:translateX(-50%);background:#334155;color:#e2e8f0;padding:.5rem 1.25rem;border-radius:8px;font-size:.8rem;opacity:0;transition:opacity .3s;pointer-events:none;z-index:100';document.body.appendChild(t)}
  t.textContent=msg;t.style.opacity='1';
  setTimeout(()=>{t.style.opacity='0'},3000);
}

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

loadData();
setInterval(loadData,10000);

(function checkInternet(){
  const banner=document.getElementById('upgrade-banner');
  if(!banner)return;
  function probe(){
    fetch('https://dance-flow-control.lovable.app/health',{mode:'no-cors',cache:'no-store'})
      .then(()=>{banner.style.display=''})
      .catch(()=>{banner.style.display='none'});
  }
  probe();
  setInterval(probe,60000);
})();

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
        drainOpQueue();
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
            const latency=m.t?(Date.now()-m.t):0;
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

// ---------------------------------------------------------------------------
// Template loading — embedded for deno compile compatibility
// ---------------------------------------------------------------------------
// deno compile does NOT bundle files read via Deno.readTextFile().
// Templates must be embedded as string literals or loaded with fallback.

let dashboardTmpl: string;
let joinTmpl: string;
let portalTmpl: string;

try {
  // Development mode: read from filesystem (allows live editing)
  const tmplDir = new URL("./templates/", import.meta.url).pathname;
  dashboardTmpl = await Deno.readTextFile(tmplDir + "dashboard.html");
  joinTmpl = await Deno.readTextFile(tmplDir + "staff-join.html");
  portalTmpl = await Deno.readTextFile(tmplDir + "portal.html");
  console.log("[EventBox] Loaded templates from filesystem");
} catch {
  // Compiled binary: use embedded fallback templates
  console.log("[EventBox] Using embedded templates (compiled mode)");

  dashboardTmpl = EMBEDDED_DASHBOARD;
  joinTmpl = EMBEDDED_JOIN;
  portalTmpl = EMBEDDED_PORTAL;
}

function renderTemplate(html: string, vars: Record<string, string>): string {
  return html.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? "");
}

// ---------------------------------------------------------------------------
// HTTP + WS server
// ---------------------------------------------------------------------------
Deno.serve({ port: PORT, hostname: "0.0.0.0" }, async (req) => {
// SERVER_START is set at module init (line 50), no need to reset per-request
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

    const html = renderTemplate(dashboardTmpl, {
      EVENT_NAME: escapeHtml(eventName),
      UPTIME: escapeHtml(uptimeStr),
      DEVICES: String(connectedDevices),
      SYNC_DOT_CLASS: Number(heatCount) > 0 ? "ok" : "none",
      HEATS: String(heatCount),
      LAST_SYNC: escapeHtml(lastSyncStr),
      ROOM_CODE: escapeHtml(ROOM_CODE),
      OPS: String(opCount),
      EVENT_ID_RAW: escapeHtml(EVENT_ID),
      JSON_EVENT_ID: JSON.stringify(EVENT_ID),
      PORT: escapeHtml(String(PORT)),
      DB_PATH: escapeHtml(DB_PATH),
      JSON_ROOM_CODE: JSON.stringify(ROOM_CODE),
      AUTO_AUTH: autoAuth ? "true" : "false",
    });
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

      case "payments": {
        const rows = queryRows(
          `SELECT credential_id, amount_cents, currency, payment_method, terminal_id, external_ref, status, confirmed_by, confirmed_at_ms FROM payments WHERE event_id=?`,
          [EVENT_ID],
        ).map(([credential_id, amount_cents, currency, payment_method, terminal_id, external_ref, status, confirmed_by, confirmed_at_ms]) => ({
          credential_id, amount_cents, currency, payment_method, terminal_id, external_ref, status, confirmed_by, confirmed_at_ms,
        }));
        return json({ event_id: EVENT_ID, payments: rows });
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

  // ---- Export all event data as JSON (for backup / data portability) ----
  if (url.pathname === "/api/export-data" && req.method === "GET") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);

    const tables: Record<string, unknown[]> = {};
    const tableNames = ["ops", "checkins", "marshal_status", "heat_status", "judge_marks", "judge_submissions", "scratches", "now_playing", "published_results", "payments", "ref_data", "staff_sessions"];
    for (const name of tableNames) {
      try {
        const rows = queryRows(`SELECT * FROM ${name} WHERE event_id=?`, [EVENT_ID]);
        // Get column names from pragma
        const colRows = queryRows(`PRAGMA table_info(${name})`, []);
        const cols = colRows.map((r) => String(r[1]));
        tables[name] = rows.map((row) => {
          const obj: Record<string, unknown> = {};
          cols.forEach((col, i) => { obj[col] = row[i]; });
          return obj;
        });
      } catch {
        tables[name] = [];
      }
    }

    const exportData = {
      event_id: EVENT_ID,
      exported_at: new Date().toISOString(),
      version: "0.4.0",
      tables,
    };

    return new Response(JSON.stringify(exportData, null, 2), {
      headers: {
        "content-type": "application/json",
        "content-disposition": `attachment; filename="eventbox-backup-${EVENT_ID.slice(0, 8)}.json"`,
        "access-control-allow-origin": "*",
      },
    });
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

    // Auto-create staff sessions from cloud event_roles + staff_profiles
    const rolesTable = body.tables.find((t: { name?: string }) => t?.name === "event_roles");
    const profilesTable = body.tables.find((t: { name?: string }) => t?.name === "staff_profiles");
    if (rolesTable && Array.isArray(rolesTable.data)) {
      const profileMap = new Map<string, { display_name?: string; email?: string }>();
      if (profilesTable && Array.isArray(profilesTable.data)) {
        for (const p of profilesTable.data) {
          if (p.user_id) profileMap.set(p.user_id, p);
        }
      }
      for (const er of rolesTable.data) {
        if (!er.user_id || !er.role) continue;
        const profile = profileMap.get(er.user_id);
        const staffName = profile?.display_name || profile?.email || `Staff (${er.role})`;
        // Upsert: don't overwrite existing sessions that may have different tokens
        const existing = queryRows(`SELECT id FROM staff_sessions WHERE event_id=? AND role=? AND staff_name=?`, [EVENT_ID, er.role, staffName]);
        if (existing.length === 0) {
          const sessionId = crypto.randomUUID();
          const joinCode = crypto.randomUUID().slice(0, 6).toUpperCase();
          const nowMs = Date.now();
          const expiresAt = nowMs + TOKEN_TTL_MS;
          queryRun(
            `INSERT INTO staff_sessions(id, event_id, role, staff_name, join_code, device_id, created_at, expires_at)
             VALUES(?,?,?,?,?,?,?,?)`,
            [sessionId, EVENT_ID, er.role, staffName, joinCode, `cloud_${er.user_id}`, String(nowMs), String(expiresAt)],
          );
        }
      }
    }

    return json({ ok: true, synced: count });
  }

  // ---- POST /api/sync-from-cloud — Pull ref data from ChasseFlow cloud ----
  if (url.pathname === "/api/sync-from-cloud" && req.method === "POST") {
    const claims = await authenticate(req);
    if (!claims) return json({ error: "unauthorized" }, 401);
    if (claims.role !== "event_admin") return json({ error: "admin only" }, 403);

    try {
      // Call the ChasséFlow eventbox-export edge function
      const supabaseUrl = Deno.env.get("EVENTBOX_SUPABASE_URL") || "https://gwbxaduxmnxaushcvlby.supabase.co";
      const cloudUrl = `${supabaseUrl}/functions/v1/eventbox-export?event_id=${encodeURIComponent(EVENT_ID)}`;
      const supabaseAnonKey = Deno.env.get("EVENTBOX_SUPABASE_ANON_KEY") || "";
      const cloudAuthToken = Deno.env.get("EVENTBOX_CLOUD_TOKEN") || "";
      const cloudRes = await fetch(cloudUrl, {
        headers: {
          "accept": "application/json",
          "apikey": supabaseAnonKey,
          ...(cloudAuthToken ? { "authorization": `Bearer ${cloudAuthToken}` } : {}),
        },
        signal: AbortSignal.timeout(15000),
      });

      if (!cloudRes.ok) {
        const errText = await cloudRes.text().catch(() => "");
        return json({
          ok: false,
          error: `ChasseFlow returned ${cloudRes.status}`,
          detail: errText.slice(0, 500),
        }, 502);
      }

      const cloudData = await cloudRes.json();

      if (!cloudData.tables || !Array.isArray(cloudData.tables)) {
        return json({ ok: false, error: "Unexpected response format from ChasseFlow" }, 502);
      }

      const now = new Date().toISOString();
      let syncCount = 0;
      for (const t of cloudData.tables) {
        if (!t?.name || t.data === undefined) continue;
        queryRun(
          `INSERT INTO ref_data(event_id, table_name, data_json, fetched_at)
           VALUES (?,?,?,?)
           ON CONFLICT(event_id, table_name) DO UPDATE SET
             data_json=excluded.data_json, fetched_at=excluded.fetched_at`,
          [EVENT_ID, t.name, JSON.stringify(t.data), now],
        );
        syncCount++;
      }

      if (cloudData.tables.some((t: { name?: string }) => t?.name === "event")) {
        refreshCachedEventName();
      }

      return json({ ok: true, synced: syncCount, source: "cloud" });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes("AbortError") || msg.includes("timeout")) {
        return json({ ok: false, error: "ChasseFlow unreachable (timeout) — are you connected to the internet?" }, 504);
      }
      return json({ ok: false, error: `Sync failed: ${msg}` }, 502);
    }
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
      wsDeviceMap.set(socket, claims.device_id);
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
      wsDeviceMap.delete(socket);
    };

    socket.onmessage = (e) => {
      try {
        const m = JSON.parse(e.data);
        if (m?.type === "ping") {
          socket.send(JSON.stringify({ type: "pong", t: m.t, time: Date.now() }));
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
      [id, EVENT_ID, body.role, body.staff_name, joinCode, String(now), String(expiresAt)],
    );

    const joinUrl = `${url.origin}/staff/join?token=${encodeURIComponent(joinCode)}`;
    return json({ id, join_code: joinCode, join_url: joinUrl, role: body.role, staff_name: body.staff_name, expires_at: expiresAt });
  }

  // POST /api/validate-code — Lightweight validation without session creation
  if (url.pathname === "/api/validate-code" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    if (!body?.code) return json({ error: "code required" }, 400);
    const code = body.code.trim().toUpperCase();

    // Check universal room code
    if (code === ROOM_CODE) {
      return json({ valid: true, type: "room_code", event_name: cachedEventName || EVENT_ID });
    }

    // Check per-staff join code
    const rows = queryRows(
      `SELECT id, role, staff_name, expires_at, revoked_at FROM staff_sessions WHERE join_code=?`,
      [code],
    );
    if (rows.length === 0) return json({ valid: false, error: "Invalid code" }, 404);
    const [, role, staffName, expiresAt, revokedAt] = rows[0];
    if (revokedAt) return json({ valid: false, error: "Session revoked" }, 403);
    if (Number(expiresAt) < Date.now()) return json({ valid: false, error: "Code expired" }, 403);
    return json({ valid: true, type: "per_staff", role, staff_name: staffName, event_name: cachedEventName || EVENT_ID });
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

    // --- Universal room code join: require staff_name and role ---
    if (code === ROOM_CODE) {
      if (!body.staff_name || !body.role) {
        return json({ error: "staff_name and role required for room code join" }, 400);
      }
      const staffName = body.staff_name;
      const role = body.role;
      const id = crypto.randomUUID();
      const joinCode = generateJoinCode();
      const now = Date.now();
      const expiresAt = now + TOKEN_TTL_MS;

      queryRun(
        `INSERT INTO staff_sessions(id, event_id, role, staff_name, join_code, device_id, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?)`,
        [id, EVENT_ID, role, staffName, joinCode, incomingDeviceId, String(now), String(expiresAt)],
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

    // Cross-reference with live WS connections for presence
    const connectedDevices = getConnectedDeviceIds();
    const rows = queryRows(
      `SELECT id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at FROM staff_sessions WHERE event_id=? AND revoked_at IS NULL ORDER BY created_at DESC`,
      [EVENT_ID],
    ).map(([id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at]) => ({
      id, role, staff_name, join_code, device_id, created_at, expires_at, revoked_at,
      online: device_id ? connectedDevices.has(String(device_id)) : false,
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

    queryRun(`UPDATE staff_sessions SET revoked_at=? WHERE id=? AND event_id=?`, [String(Date.now()), body.session_id, EVENT_ID]);
    return json({ ok: true });
  }

  // GET /staff/join — Two paths: token-based scan-and-go OR manual room code
  if (url.pathname === "/staff/join" && req.method === "GET") {
    const joinCode = url.searchParams.get("join") || "";
    const tokenParam = url.searchParams.get("token") || "";
    const eventName = cachedEventName || EVENT_ID.slice(0, 8) + "…";
    const html = renderTemplate(joinTmpl, {
      EVENT_NAME: escapeHtml(eventName),
      JOIN_CODE: escapeHtml(joinCode),
      JSON_TOKEN_PARAM: JSON.stringify(tokenParam),
      JSON_JOIN_CODE: JSON.stringify(joinCode),
    });
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
    queryRun(`UPDATE staff_sessions SET expires_at=? WHERE id=?`, [String(newExpiry), id]);

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
    const kioskId = url.searchParams.get("kiosk") || "";

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
    const safeKioskId = JSON.stringify(kioskId);

    // Build role-specific script
    let roleScript = "";
    if (role === "scanner") {
      roleScript = `
let credentials=[];
let checkins={};
let payments={};
let searchTerm='';

async function loadData(){
  try{
    const [ciRes, credRef, payRes]=await Promise.all([
      api('/state/checkins'),
      fetch(BASE+'/state/ref?table=credentials',{headers:AUTH}).then(r=>r.json()).catch(()=>null),
      api('/state/payments').catch(()=>({payments:[]}))
    ]);
    credentials=[];
    const ciMap={};
    (ciRes.checkins||[]).forEach(c=>ciMap[c.credential_id]=c.status);
    checkins=ciMap;
    const payMap={};
    (payRes.payments||[]).forEach(p=>payMap[p.credential_id]=p);
    payments=payMap;
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
    const paid=payments[c.id];
    const paidMethod=paid&&paid.payment_method?esc(paid.payment_method):'';
    const paidLabel=paid&&paid.status==='confirmed'?('$ Paid'+(paidMethod?' ('+paidMethod+')':'')):'$ Unpaid';
    const paidColor=paid&&paid.status==='confirmed'?'#4ade80':'#f59e0b';
    const paidBadge='<span style="color:'+paidColor+';font-size:.7rem;margin-left:.5rem">'+paidLabel+'</span>';
    const payBtn=(!paid||paid.status!=='confirmed')?'<button class="btn" style="background:#f59e0b;color:#000;margin-right:.25rem;font-size:.75rem;padding:.35rem .6rem" onclick="markPaid(\\''+c.id+'\\')">$ Paid</button>':'';
    html+='<div class="list-item"><div class="num">'+(c.competitor_number||'—')+'</div><div class="info"><div class="name">'+esc(c.person_name||'Unknown')+'</div><div class="detail">'+esc(c.credential_type||'competitor')+paidBadge+'</div></div>'+payBtn+'<button class="btn btn-check" onclick="doCheckin(\\''+c.id+'\\')">Check In</button></div>';
  });
  checked.forEach(c=>{
    const paid=payments[c.id];
    const paidMethod=paid&&paid.payment_method?esc(paid.payment_method):'';
    const paidLabel=paid&&paid.status==='confirmed'?('$ Paid'+(paidMethod?' ('+paidMethod+')':'')):'$ Unpaid';
    const paidColor=paid&&paid.status==='confirmed'?'#4ade80':'#f59e0b';
    const paidBadge='<span style="color:'+paidColor+';font-size:.7rem;margin-left:.5rem">'+paidLabel+'</span>';
    html+='<div class="list-item" style="opacity:.6"><div class="num">'+(c.competitor_number||'—')+'</div><div class="info"><div class="name">'+esc(c.person_name||'Unknown')+'</div><div class="detail">✅ Checked in'+paidBadge+'</div></div><button class="btn btn-checked" disabled>Done</button></div>';
  });
  document.getElementById('portal-root').innerHTML=html;
}

async function doCheckin(credId){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'checkin',created_at_ms:Date.now(),payload:{credential_id:credId,status:'checked_in'}};
  const result=await submitOp(op);
  if(result.queued){
    checkins[credId]='checked_in';
  }else if(result.ok&&result.results){
    const r=result.results[0];
    if(r&&r.accepted){checkins[credId]='checked_in'}
    else if(r&&(r.reason==='duplicate'||r.reason==='fsm_rejected')){
      const who=r.detail?.updated_by||'another staff';
      portalToast('Already checked in by '+who);
    }
  }
  render();
}

async function markPaid(credId){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'payment_confirmed',created_at_ms:Date.now(),payload:{credential_id:credId,status:'confirmed',payment_method:'cash'}};
  await submitOp(op);
  payments[credId]={credential_id:credId,status:'confirmed',payment_method:'cash'};
  render();
}
`;
    } else if (role === "marshal" || role === "deck_captain" || role === "floor_captain") {
      roleScript = `
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
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heats=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
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
  const result=await submitOp(op);
  if(result.queued){
    heatStatuses[heatId]=newStatus;
    portalToast('Queued offline — will sync when reconnected');
  }else if(result.ok&&result.results){
    const r=result.results[0];
    if(r&&r.accepted){heatStatuses[heatId]=newStatus}
    else if(r&&r.reason==='fsm_rejected'){
      const who=r.detail?.updated_by||'another marshal';
      const current=r.detail?.current_status||'already updated';
      portalToast('Already '+current.replace('_',' ')+' by '+who);
      await loadData();return;
    }else if(r&&r.reason==='duplicate'){portalToast('Already recorded')}
  }
  render();
}
`;
    } else if (role === "announcer" || role === "dj") {
      roleScript = `
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
`;
    } else if (role === "judge") {
      roleScript = `
let heatsData=[];
let heatStatuses={};
let divisions={};
let currentHeatId=null;
let currentDanceIdx=0;
let marks={};
let submissions={};

async function loadData(){
  try{
    const [hsRes]=await Promise.all([api('/state/heats')]);
    heatStatuses={};
    (hsRes.heats||[]).forEach(h=>heatStatuses[h.heat_id]=h.status);
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heatsData=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
      heatsData=Object.keys(heatStatuses).map(id=>({id,heat_number:null,division_name:null,dances:[]}));
    }
    const divRef=await fetch(BASE+'/state/ref?table=divisions',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(divRef?.data){
      const divArr=typeof divRef.data==='string'?JSON.parse(divRef.data):divRef.data;
      divArr.forEach(d=>{divisions[d.id]=d});
    }
    // Load existing marks
    try{
      const mRes=await api('/state/judge-marks');
      (mRes.marks||[]).forEach(m=>{marks[m.heat_id+'_'+m.dance_code+'_'+m.heat_entry_id]=m});
    }catch{}
    try{
      const sRes=await api('/state/judge-submissions');
      (sRes.submissions||[]).forEach(s=>{submissions[s.heat_id+'_'+s.dance_code]=s});
    }catch{}
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  if(currentHeatId){renderScoring();return}
  const active=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='on_floor'||s==='on_deck'});
  const scheduled=heatsData.filter(h=>{const s=heatStatuses[h.id];return !s||s==='scheduled'||s==='in_hole'});
  const completed=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='completed'});
  let html='<h3 style="font-size:.9rem;color:#fff;margin-bottom:.75rem">🎯 Heats to Score</h3>';
  if(active.length===0&&scheduled.length===0){
    html+='<div class="empty"><p>No heats available for scoring yet.</p><p style="color:#4ade80;font-size:.75rem;margin-top:.5rem">✓ Connected — heats will appear when marshalled.</p></div>';
  }
  [...active,...scheduled].forEach(h=>{
    const status=heatStatuses[h.id]||'scheduled';
    const isOnFloor=status==='on_floor';
    html+='<div class="list-item" style="cursor:pointer;'+(isOnFloor?'border-color:#6366f1':'')+'" onclick="openHeat(\\''+h.id+'\\')"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status '+status+'">'+status.replace('_',' ')+'</span></div></div><span style="color:#6366f1;font-size:.8rem">Score →</span></div>';
  });
  if(completed.length>0){
    html+='<h3 style="font-size:.85rem;color:#94a3b8;margin:1rem 0 .5rem">Completed ('+completed.length+')</h3>';
    completed.slice(0,10).forEach(h=>{
      html+='<div class="list-item" style="opacity:.5"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status completed">completed</span></div></div></div>';
    });
  }
  document.getElementById('portal-root').innerHTML=html;
}

function openHeat(heatId){
  currentHeatId=heatId;
  currentDanceIdx=0;
  renderScoring();
}

function renderScoring(){
  const heat=heatsData.find(h=>h.id===currentHeatId);
  if(!heat){currentHeatId=null;render();return}
  const div=heat.division_id?divisions[heat.division_id]:null;
  const dances=(heat.dances&&heat.dances.length>0)?heat.dances:(div&&div.dances?div.dances:[{dance_code:'dance',dance_name:'Dance'}]);
  const dance=dances[currentDanceIdx]||dances[0]||{dance_code:'dance',dance_name:'Dance'};
  const scoringMode=div?div.scoring_mode:'callback';
  const entries=heat.entries||[];

  let html='<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:1rem"><button class="btn" style="background:#334155;color:#e2e8f0;padding:.4rem .7rem" onclick="currentHeatId=null;render()">← Back</button><div><div style="font-size:1rem;font-weight:700;color:#fff">Heat '+(heat.heat_number||'—')+'</div><div style="font-size:.75rem;color:#94a3b8">'+(heat.division_name||'')+'</div></div></div>';

  // Dance tabs
  if(dances.length>1){
    html+='<div class="tabs">';
    dances.forEach((d,i)=>{
      const subKey=currentHeatId+'_'+d.dance_code;
      const submitted=!!submissions[subKey];
      html+='<div class="tab '+(i===currentDanceIdx?'active':'')+'" onclick="currentDanceIdx='+i+';renderScoring()">'+(d.dance_name||d.dance_code)+(submitted?' ✓':'')+'</div>';
    });
    html+='</div>';
  }

  // Scoring area
  if(entries.length===0){
    html+='<div class="empty">No entries loaded for this heat. Sync event data to see competitors.</div>';
  }else if(scoringMode==='callback'){
    html+='<p style="font-size:.75rem;color:#94a3b8;margin-bottom:.75rem">Tap competitors to mark callbacks:</p>';
    entries.forEach((e,i)=>{
      const markKey=currentHeatId+'_'+dance.dance_code+'_'+e.id;
      const marked=!!marks[markKey];
      html+='<div class="list-item" style="cursor:pointer;'+(marked?'border-color:#22c55e;background:#22c55e10':'')+'" onclick="toggleCallback(\\''+e.id+'\\',\\''+dance.dance_code+'\\')"><div class="num">'+(e.competitor_number||i+1)+'</div><div class="info"><div class="name">'+(e.competitor_name||'Competitor '+(i+1))+'</div></div><span style="font-size:1.2rem">'+(marked?'✅':'⬜')+'</span></div>';
    });
  }else{
    html+='<p style="font-size:.75rem;color:#94a3b8;margin-bottom:.75rem">Enter ordinal placements (1 = best):</p>';
    entries.forEach((e,i)=>{
      const markKey=currentHeatId+'_'+dance.dance_code+'_'+e.id;
      const existing=marks[markKey];
      const val=existing?existing.ordinal:'';
      html+='<div class="list-item"><div class="num">'+(e.competitor_number||i+1)+'</div><div class="info"><div class="name">'+(e.competitor_name||'Competitor '+(i+1))+'</div></div><input type="number" min="1" max="'+entries.length+'" value="'+val+'" style="width:3rem;padding:.3rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff;text-align:center;font-size:1rem" onchange="setOrdinal(\\''+e.id+'\\',\\''+dance.dance_code+'\\',this.value)"></div>';
    });
  }

  // Submit button
  const subKey=currentHeatId+'_'+dance.dance_code;
  const alreadySubmitted=!!submissions[subKey];
  html+='<div style="margin-top:1rem"><button class="btn '+(alreadySubmitted?'btn-checked':'btn-check')+'" style="width:100%;padding:.7rem" onclick="submitDance(\\''+dance.dance_code+'\\',\\''+dance.dance_name+'\\')">'+(alreadySubmitted?'✓ Submitted — Tap to Resubmit':'Submit '+esc(dance.dance_name||dance.dance_code))+'</button></div>';

  document.getElementById('portal-root').innerHTML=html;
}

function toggleCallback(entryId,danceCode){
  const markKey=currentHeatId+'_'+danceCode+'_'+entryId;
  if(marks[markKey]){delete marks[markKey]}
  else{marks[markKey]={heat_id:currentHeatId,dance_code:danceCode,heat_entry_id:entryId,callback:true}}
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'score',created_at_ms:Date.now(),payload:{heat_id:currentHeatId,dance_code:danceCode,heat_entry_id:entryId,callback:!!marks[markKey]}};
  submitOp(op);
  renderScoring();
}

function setOrdinal(entryId,danceCode,val){
  const markKey=currentHeatId+'_'+danceCode+'_'+entryId;
  const ordinal=parseInt(val)||null;
  if(ordinal){marks[markKey]={heat_id:currentHeatId,dance_code:danceCode,heat_entry_id:entryId,ordinal:ordinal}}
  else{delete marks[markKey]}
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'score',created_at_ms:Date.now(),payload:{heat_id:currentHeatId,dance_code:danceCode,heat_entry_id:entryId,ordinal:ordinal}};
  submitOp(op);
}

async function submitDance(danceCode,danceName){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'score_submission',created_at_ms:Date.now(),payload:{heat_id:currentHeatId,dance_code:danceCode}};
  const result=await submitOp(op);
  submissions[currentHeatId+'_'+danceCode]={heat_id:currentHeatId,dance_code:danceCode};
  portalToast('Submitted '+(danceName||danceCode));
  renderScoring();
}
`;
    } else if (role === "scrutineer") {
      roleScript = `
let heatsData=[];
let heatStatuses={};
let divisions={};
let judgeMarks={};
let judgeSubmissions={};
let currentHeatId=null;

async function loadData(){
  try{
    const [hsRes]=await Promise.all([api('/state/heats')]);
    heatStatuses={};
    (hsRes.heats||[]).forEach(h=>heatStatuses[h.heat_id||h.id]=h.status);
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heatsData=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
      heatsData=Object.keys(heatStatuses).map(id=>({id,heat_number:null,division_name:null,dances:[],entries:[]}));
    }
    const divRef=await fetch(BASE+'/state/ref?table=divisions',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(divRef?.data){
      const divArr=typeof divRef.data==='string'?JSON.parse(divRef.data):divRef.data;
      divArr.forEach(d=>{divisions[d.id]=d});
    }
    try{
      const mRes=await api('/state/judge-marks');
      judgeMarks={};
      (mRes.marks||[]).forEach(m=>{
        const key=m.heat_id+'_'+m.dance_code;
        if(!judgeMarks[key])judgeMarks[key]=[];
        judgeMarks[key].push(m);
      });
    }catch{}
    try{
      const sRes=await api('/state/judge-submissions');
      judgeSubmissions={};
      (sRes.submissions||[]).forEach(s=>{
        const key=s.heat_id+'_'+s.dance_code;
        if(!judgeSubmissions[key])judgeSubmissions[key]=[];
        judgeSubmissions[key].push(s);
      });
    }catch{}
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  if(currentHeatId){renderHeatDetail();return}
  const active=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='on_floor'||s==='on_deck'});
  const scheduled=heatsData.filter(h=>{const s=heatStatuses[h.id];return !s||s==='scheduled'||s==='in_hole'});
  const completed=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='completed'});
  let html='<h3 style="font-size:.9rem;color:#fff;margin-bottom:.75rem">📋 Mark Monitor</h3>';
  if(heatsData.length===0){
    html+='<div class="empty"><p>No heats loaded yet.</p><button class="btn btn-floor" style="margin-top:.5rem" onclick="loadData()">Refresh</button></div>';
  }
  [...active,...scheduled].forEach(h=>{
    const status=heatStatuses[h.id]||'scheduled';
    const div=h.division_id?divisions[h.division_id]:null;
    const dances=(h.dances&&h.dances.length>0)?h.dances:(div&&div.dances?div.dances:[]);
    const totalDances=dances.length||1;
    let submittedDances=0;
    dances.forEach(d=>{
      const key=h.id+'_'+d.dance_code;
      if(judgeSubmissions[key]&&judgeSubmissions[key].length>0)submittedDances++;
    });
    const pct=totalDances>0?Math.round(submittedDances/totalDances*100):0;
    html+='<div class="list-item" style="cursor:pointer" onclick="openHeatDetail(\\''+h.id+'\\')"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status '+status+'">'+status.replace('_',' ')+'</span> · '+pct+'% scored</div></div><span style="color:#6366f1;font-size:.8rem">Detail →</span></div>';
  });
  if(completed.length>0){
    html+='<h3 style="font-size:.85rem;color:#94a3b8;margin:1rem 0 .5rem">Completed ('+completed.length+')</h3>';
    completed.forEach(h=>{
      html+='<div class="list-item" style="cursor:pointer;opacity:.6" onclick="openHeatDetail(\\''+h.id+'\\')"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status completed">completed</span></div></div><span style="color:#6366f1;font-size:.8rem">Detail →</span></div>';
    });
  }
  document.getElementById('portal-root').innerHTML=html;
}

function openHeatDetail(heatId){currentHeatId=heatId;render()}

function renderHeatDetail(){
  const heat=heatsData.find(h=>h.id===currentHeatId);
  if(!heat){currentHeatId=null;render();return}
  const div=heat.division_id?divisions[heat.division_id]:null;
  const dances=(heat.dances&&heat.dances.length>0)?heat.dances:(div&&div.dances?div.dances:[{dance_code:'dance',dance_name:'Dance'}]);
  const entries=heat.entries||[];
  const status=heatStatuses[currentHeatId]||'scheduled';

  let html='<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:1rem"><button class="btn" style="background:#334155;color:#e2e8f0;padding:.4rem .7rem" onclick="currentHeatId=null;render()">← Back</button><div><div style="font-size:1rem;font-weight:700;color:#fff">Heat '+(heat.heat_number||'—')+' · '+esc(heat.division_name||'')+'</div><div style="font-size:.75rem;color:#94a3b8"><span class="heat-status '+status+'">'+status.replace('_',' ')+'</span></div></div></div>';

  // Mark summary table
  html+='<div style="margin-bottom:1rem"><h4 style="font-size:.8rem;color:#94a3b8;margin-bottom:.5rem">Submissions by Dance</h4>';
  html+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.75rem"><thead><tr style="border-bottom:1px solid #334155"><th style="text-align:left;padding:.3rem .5rem;color:#64748b">Dance</th><th style="text-align:center;padding:.3rem .5rem;color:#64748b">Marks</th><th style="text-align:center;padding:.3rem .5rem;color:#64748b">Submitted</th></tr></thead><tbody>';
  dances.forEach(d=>{
    const markKey=currentHeatId+'_'+d.dance_code;
    const markCount=(judgeMarks[markKey]||[]).length;
    const subCount=(judgeSubmissions[markKey]||[]).length;
    const isComplete=subCount>0;
    html+='<tr style="border-bottom:1px solid #1e293b"><td style="padding:.3rem .5rem;color:#e2e8f0">'+(d.dance_name||d.dance_code)+'</td><td style="text-align:center;padding:.3rem .5rem;color:#94a3b8">'+markCount+'</td><td style="text-align:center;padding:.3rem .5rem;color:'+(isComplete?'#4ade80':'#f59e0b')+'">'+(isComplete?'✓ '+subCount:'pending')+'</td></tr>';
  });
  html+='</tbody></table></div></div>';

  // Verify results button
  if(status==='completed'){
    html+='<button class="btn btn-check" style="width:100%;padding:.7rem;margin-bottom:.75rem" onclick="verifyResults(\\''+currentHeatId+'\\')">✓ Verify Results</button>';
  }

  // Entries
  if(entries.length>0){
    html+='<h4 style="font-size:.8rem;color:#94a3b8;margin-bottom:.5rem">Entries ('+entries.length+')</h4>';
    entries.forEach((e,i)=>{
      html+='<div class="list-item"><div class="num">'+(e.competitor_number||i+1)+'</div><div class="info"><div class="name">'+(e.competitor_name||'Competitor '+(i+1))+'</div></div></div>';
    });
  }
  document.getElementById('portal-root').innerHTML=html;
}

async function verifyResults(heatId){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'result_publish',created_at_ms:Date.now(),payload:{heat_id:heatId,placements:[],checksum:'scrutineer-verified'}};
  await submitOp(op);
  portalToast('Results verified for heat');
}
`;
    } else if (role === "chairman") {
      roleScript = `
let heatsData=[];
let heatStatuses={};
let divisions={};
let currentHeatId=null;

async function loadData(){
  try{
    const [hsRes]=await Promise.all([api('/state/heats')]);
    heatStatuses={};
    (hsRes.heats||[]).forEach(h=>heatStatuses[h.heat_id||h.id]=h.status);
    const heatRef=await fetch(BASE+'/state/ref?table=heats',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(heatRef?.data){
      heatsData=typeof heatRef.data==='string'?JSON.parse(heatRef.data):heatRef.data;
    }else{
      heatsData=Object.keys(heatStatuses).map(id=>({id,heat_number:null,division_name:null}));
    }
    const divRef=await fetch(BASE+'/state/ref?table=divisions',{headers:AUTH}).then(r=>r.json()).catch(()=>null);
    if(divRef?.data){
      const divArr=typeof divRef.data==='string'?JSON.parse(divRef.data):divRef.data;
      divArr.forEach(d=>{divisions[d.id]=d});
    }
    render();
  }catch(e){
    document.getElementById('portal-root').innerHTML='<div class="empty">⚠ Could not load data: '+esc(e.message)+'<br><button class="btn btn-floor" style="margin-top:1rem" onclick="loadData()">Retry</button></div>';
  }
}

function render(){
  if(currentHeatId){renderHeatControls();return}
  const active=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='on_floor'||s==='on_deck'});
  const scheduled=heatsData.filter(h=>{const s=heatStatuses[h.id];return !s||s==='scheduled'||s==='in_hole'});
  const completed=heatsData.filter(h=>{const s=heatStatuses[h.id];return s==='completed'});
  let html='<h3 style="font-size:.9rem;color:#fff;margin-bottom:.75rem">⚖ Chairman Controls</h3>';
  [...active,...scheduled].forEach(h=>{
    const status=heatStatuses[h.id]||'scheduled';
    const isOnFloor=status==='on_floor';
    html+='<div class="list-item" style="cursor:pointer;'+(isOnFloor?'border-color:#f59e0b':'')+'" onclick="openHeatCtrl(\\''+h.id+'\\')"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status '+status+'">'+status.replace('_',' ')+'</span></div></div><span style="color:#f59e0b;font-size:.8rem">Control →</span></div>';
  });
  if(completed.length>0){
    html+='<h3 style="font-size:.85rem;color:#94a3b8;margin:1rem 0 .5rem">Completed ('+completed.length+')</h3>';
    completed.slice(0,10).forEach(h=>{
      html+='<div class="list-item" style="opacity:.5"><div class="num">'+(h.heat_number||'—')+'</div><div class="info"><div class="name">'+(h.division_name||'Heat')+'</div><div class="detail"><span class="heat-status completed">completed</span></div></div></div>';
    });
  }
  document.getElementById('portal-root').innerHTML=html;
}

function openHeatCtrl(heatId){currentHeatId=heatId;render()}

function renderHeatControls(){
  const heat=heatsData.find(h=>h.id===currentHeatId);
  if(!heat){currentHeatId=null;render();return}
  const status=heatStatuses[currentHeatId]||'scheduled';
  let html='<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:1rem"><button class="btn" style="background:#334155;color:#e2e8f0;padding:.4rem .7rem" onclick="currentHeatId=null;render()">← Back</button><div><div style="font-size:1rem;font-weight:700;color:#fff">Heat '+(heat.heat_number||'—')+'</div><div style="font-size:.75rem;color:#94a3b8">'+(heat.division_name||'')+'</div></div></div>';

  html+='<div style="font-size:.8rem;color:#94a3b8;margin-bottom:1rem">Current status: <span class="heat-status '+status+'" style="font-size:.8rem">'+status.replace('_',' ')+'</span></div>';

  // Round progression
  html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:1rem">';
  const transitions=[
    {to:'on_deck',label:'→ On Deck',show:status==='scheduled'||status==='in_hole'},
    {to:'on_floor',label:'→ On Floor',show:status==='on_deck'||status==='scheduled'},
    {to:'completed',label:'✓ Complete',show:status==='on_floor'},
    {to:'cancelled',label:'✗ Cancel',show:status!=='completed'&&status!=='cancelled'},
  ];
  transitions.filter(t=>t.show).forEach(t=>{
    html+='<button class="btn '+(t.to==='completed'?'btn-check':t.to==='cancelled'?'btn-off':'btn-floor')+'" style="padding:.6rem;font-size:.8rem" onclick="setHeatStatus(\\''+t.to+'\\')">'+t.label+'</button>';
  });
  html+='</div>';

  // Chairman overrides
  html+='<h4 style="font-size:.8rem;color:#94a3b8;margin-bottom:.5rem">Overrides</h4>';
  html+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:1rem">';
  html+='<button class="btn" style="background:#334155;color:#e2e8f0;padding:.5rem;font-size:.8rem" onclick="chairmanOverride(\\'skip\\')">⏭ Skip Heat</button>';
  html+='<button class="btn" style="background:#334155;color:#e2e8f0;padding:.5rem;font-size:.8rem" onclick="chairmanOverride(\\'recall\\')">🔄 Recall</button>';
  html+='<button class="btn" style="background:#334155;color:#e2e8f0;padding:.5rem;font-size:.8rem" onclick="chairmanOverride(\\'restart\\')">⟳ Restart</button>';
  html+='<button class="btn" style="background:#334155;color:#e2e8f0;padding:.5rem;font-size:.8rem" onclick="chairmanOverride(\\'complete\\')">✓ Force Complete</button>';
  html+='</div>';

  // Recall limit
  html+='<div style="margin-bottom:1rem"><label style="font-size:.75rem;color:#94a3b8;display:block;margin-bottom:.3rem">Recall Limit (callback rounds):</label><input type="number" id="recall-limit" min="1" max="99" value="'+(heat.recall_limit||'')+ '" placeholder="e.g. 12" style="width:5rem;padding:.3rem;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#fff;text-align:center;font-size:.9rem"></div>';

  document.getElementById('portal-root').innerHTML=html;
}

async function setHeatStatus(newStatus){
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'heat_state',created_at_ms:Date.now(),payload:{heat_id:currentHeatId,status:newStatus}};
  await submitOp(op);
  heatStatuses[currentHeatId]=newStatus;
  portalToast('Heat → '+newStatus.replace('_',' '));
  render();
}

async function chairmanOverride(action){
  const reason=prompt('Reason for '+action+' (optional):');
  const op={op_id:crypto.randomUUID(),event_id:EVENT_ID,op_type:'chairman_override',created_at_ms:Date.now(),payload:{heat_id:currentHeatId,action:action,reason:reason||''}};
  await submitOp(op);
  portalToast('Override: '+action);
  if(action==='skip'||action==='complete'){heatStatuses[currentHeatId]='completed'}
  else if(action==='restart'){heatStatuses[currentHeatId]='on_floor'}
  render();
}
`;
    } else {
      roleScript = `
async function loadData(){
  document.getElementById('portal-root').innerHTML='<div class="empty"><p style="font-size:1.1rem;margin-bottom:.5rem">📋 ${escapeHtml(title)}</p><p>This role\\'s full features are available in the <a href="https://dance-flow-control.lovable.app" style="color:#818cf8">full app</a>.</p><p style="margin-top:1rem">Basic event status:</p><div id="status-info" style="margin-top:.75rem">Loading…</div></div>';
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
`;
    }

    const html = renderTemplate(portalTmpl, {
      TITLE: escapeHtml(title),
      ROLE: escapeHtml(role),
      JSON_TOKEN: safeToken,
      JSON_EVENT_ID: safeEventId,
      JSON_ROLE: safeRole,
      JSON_KIOSK_ID: safeKioskId,
      ROLE_SCRIPT: roleScript,
    });
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
