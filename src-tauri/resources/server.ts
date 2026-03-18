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
// Template loading (read once at startup)
// ---------------------------------------------------------------------------
const TMPL_DIR = new URL("./templates/", import.meta.url).pathname;
const dashboardTmpl = await Deno.readTextFile(TMPL_DIR + "dashboard.html");
const joinTmpl = await Deno.readTextFile(TMPL_DIR + "staff-join.html");
const portalTmpl = await Deno.readTextFile(TMPL_DIR + "portal.html");

function renderTemplate(html: string, vars: Record<string, string>): string {
  return html.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? "");
}

// ---------------------------------------------------------------------------
// HTTP + WS server
// ---------------------------------------------------------------------------
Deno.serve({ port: PORT }, async (req) => {
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
      room_code: ROOM_CODE,
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
          const expiresAt = Date.now() + TOKEN_TTL_MS;
          queryRun(
            `INSERT INTO staff_sessions(id, event_id, role, staff_name, join_code, device_id, created_at, expires_at)
             VALUES(?,?,?,?,?,?,?,?)`,
            [sessionId, EVENT_ID, er.role, staffName, joinCode, `cloud_${er.user_id}`, Date.now(), expiresAt],
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

    queryRun(`UPDATE staff_sessions SET revoked_at=? WHERE id=? AND event_id=?`, [Date.now(), body.session_id, EVENT_ID]);
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
