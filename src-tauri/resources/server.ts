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
const ROOM_CODE =
  Deno.env.get("EVENTBOX_ROOM_CODE") ??
  String(Math.floor(100000 + Math.random() * 900000));
const EVENT_ID = Deno.env.get("EVENTBOX_EVENT_ID") ?? "";
const SECRET =
  Deno.env.get("EVENTBOX_SECRET") ??
  crypto.randomUUID().replace(/-/g, "");

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

// HTML escape helper — prevents XSS in server-rendered templates
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
`);

// ---------------------------------------------------------------------------
// Helper: run a query that returns rows as arrays of values
// ---------------------------------------------------------------------------
function queryRows(sql: string, params: unknown[] = []): unknown[][] {
  const stmt = db.prepare(sql);
  const rows: unknown[][] = [];
  for (const row of stmt.iter(...params)) {
    rows.push(row as unknown[]);
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
  | { accepted: false; reason: "duplicate" | "fsm_rejected" | "invalid" | "wrong_event" };

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

  const now = Date.now();

  // Wrap entire op application in a transaction for atomicity.
  // If FSM rejects, the op log INSERT is rolled back too.
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

    // 3. Commit the transaction — op log + materialized state are consistent
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }

  // 4. Broadcast to all connected peers (outside transaction)
  broadcastToEvent(op.event_id, { type: "op.applied", op });

  return { accepted: true };
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

// ---------------------------------------------------------------------------
// HTTP + WS server
// ---------------------------------------------------------------------------
Deno.serve({ port: PORT }, async (req) => {
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

  // ---- Root landing page ----
  if (url.pathname === "/" && req.method === "GET") {
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — ${escapeHtml(EVENT_ID.slice(0,8))}</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:480px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{margin:0 0 .25rem;font-size:1.5rem;color:#fff}.badge{display:inline-block;background:#22c55e;color:#fff;font-size:.7rem;padding:2px 8px;border-radius:9999px;vertical-align:middle;margin-left:.5rem}
.info{margin:1.5rem 0;background:#0f172a;border-radius:8px;padding:1rem;font-family:monospace;font-size:.85rem;line-height:1.8}
.label{color:#94a3b8}.val{color:#38bdf8}
.code{font-size:2rem;letter-spacing:.3em;text-align:center;color:#f59e0b;font-weight:700;margin:1rem 0}
.hint{font-size:.8rem;color:#64748b;margin-top:1rem;line-height:1.5}
a{color:#818cf8}hr{border:none;border-top:1px solid #334155;margin:1.5rem 0}
.actions{display:flex;gap:.75rem;margin-top:1rem}
.actions a{flex:1;text-align:center;padding:.6rem;border-radius:8px;background:#334155;color:#e2e8f0;text-decoration:none;font-size:.85rem}
.actions a:hover{background:#475569}
</style></head>
<body><div class="card">
<h1>EventBox<span class="badge">Running</span></h1>
<p style="color:#94a3b8;font-size:.85rem;margin-top:.25rem">LAN Authority Server v0.3</p>
<div class="info">
<span class="label">Event ID:</span> <span class="val">${escapeHtml(EVENT_ID)}</span><br>
<span class="label">Port:</span> <span class="val">${escapeHtml(String(PORT))}</span><br>
<span class="label">Database:</span> <span class="val">${escapeHtml(DB_PATH)}</span>
</div>
<p style="color:#94a3b8;font-size:.85rem">Room Code:</p>
<div class="code">${escapeHtml(ROOM_CODE)}</div>
<p class="hint">Share this code with staff devices to connect. They can join at <strong>/staff</strong> or enter the code in the PWA.</p>
<hr>
<div class="actions">
<a href="/health">Health Check</a>
<a href="/staff">Staff Join</a>
</div>
<p class="hint" style="margin-top:1.5rem">📱 Staff devices should connect to this machine's local IP on port ${escapeHtml(String(PORT))}. The PWA app will auto-detect the EventBox when configured.</p>
</div></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // ---- Health (unauthenticated — needed for discovery) ----
  if (url.pathname === "/health") {
    const accept = req.headers.get("accept") || "";
    if (accept.includes("text/html")) {
      // Browser — show nice page
      const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Health Check</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);text-align:center}
h1{margin:0 0 .25rem;font-size:1.5rem;color:#fff}
.badge{display:inline-block;background:#22c55e;color:#fff;font-size:.75rem;padding:3px 12px;border-radius:9999px;margin:.75rem 0;font-weight:600}
.info{margin:1rem 0;background:#0f172a;border-radius:8px;padding:1rem;font-family:monospace;font-size:.85rem;line-height:1.8;text-align:left}
.label{color:#94a3b8}.val{color:#38bdf8}
.back{display:block;text-align:center;margin-top:1.5rem;color:#818cf8;font-size:.85rem;text-decoration:none}
.back:hover{text-decoration:underline}
</style></head>
<body><div class="card">
<h1>Health Check</h1>
<div class="badge">✓ All Systems OK</div>
<div class="info">
<span class="label">Status:</span> <span class="val">Running</span><br>
<span class="label">Event ID:</span> <span class="val">${escapeHtml(EVENT_ID)}</span><br>
<span class="label">Version:</span> <span class="val">0.3.0</span><br>
<span class="label">Time:</span> <span class="val">${escapeHtml(new Date().toISOString())}</span><br>
<span class="label">Port:</span> <span class="val">${escapeHtml(String(PORT))}</span>
</div>
<a class="back" href="/">← Back to Dashboard</a>
</div></body></html>`;
      return new Response(html, { headers: { "content-type": "text/html" } });
    }
    return json({
      ok: true,
      time: Date.now(),
      event_id: EVENT_ID,
      version: "0.3.0",
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
    if (body?.room_code !== ROOM_CODE) {
      return json({ ok: false, error: "invalid_room_code" }, 401);
    }
    const deviceId = body.device_id ?? crypto.randomUUID();
    const role = body.role ?? "event_admin";
    const token = await issueToken(deviceId, role);
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
        version: "0.3.0",
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
    // Generate 6 fully random base-36 characters (0-9, A-Z)
    // Uses 6 random bytes, each mapped to a base-36 char
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

    const joinUrl = `${url.origin}/staff?join=${joinCode}`;
    return json({ id, join_code: joinCode, join_url: joinUrl, role: body.role, staff_name: body.staff_name, expires_at: expiresAt });
  }

  // POST /api/staff-sessions/join — Volunteer claims a code (NO auth required)
  if (url.pathname === "/api/staff-sessions/join" && req.method === "POST") {
    const body = await req.json().catch(() => null);
    if (!body?.join_code) {
      return json({ error: "join_code required" }, 400);
    }

    const rows = queryRows(
      `SELECT id, event_id, role, staff_name, expires_at, revoked_at FROM staff_sessions WHERE join_code=?`,
      [body.join_code.toUpperCase()],
    );

    if (rows.length === 0) return json({ error: "Invalid join code" }, 404);
    const [id, eventId, role, staffName, expiresAt, revokedAt] = rows[0];

    if (revokedAt) return json({ error: "This session has been revoked" }, 403);
    if (Number(expiresAt) < Date.now()) return json({ error: "This join code has expired" }, 403);

    const incomingDeviceId = body.device_id || crypto.randomUUID();

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

  // GET /staff/join — Self-contained join page (works on localhost without PWA)
  if (url.pathname === "/staff/join" && req.method === "GET") {
    const joinCode = url.searchParams.get("join") || "";
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Staff Join</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{margin:0 0 .5rem;font-size:1.5rem;color:#fff;text-align:center}
.subtitle{text-align:center;color:#94a3b8;font-size:.85rem;margin-bottom:1.5rem}
input{width:100%;padding:.85rem;border-radius:8px;border:2px solid #334155;background:#0f172a;color:#fff;font-size:1.3rem;text-align:center;letter-spacing:.3em;margin:.75rem 0;outline:none;transition:border-color .2s}
input:focus{border-color:#6366f1}
button{width:100%;padding:.85rem;border-radius:8px;border:none;background:#6366f1;color:#fff;font-size:1rem;cursor:pointer;font-weight:600;transition:background .2s}
button:hover{background:#4f46e5}button:disabled{opacity:.5;cursor:not-allowed}
.msg{margin-top:1rem;font-size:.85rem;text-align:center;min-height:1.2em}
.msg.error{color:#f87171}.msg.success{color:#4ade80}.msg.loading{color:#94a3b8}
.back{display:block;text-align:center;margin-top:1.5rem;color:#818cf8;font-size:.85rem;text-decoration:none}
.back:hover{text-decoration:underline}
.role-badge{display:inline-block;background:#22c55e20;color:#4ade80;padding:2px 10px;border-radius:99px;font-size:.8rem;font-weight:600}
</style></head>
<body><div class="card">
<h1>Staff Join</h1>
<p class="subtitle">Enter your join code to connect</p>
<input id="code" placeholder="ABC123" maxlength="8" value="${escapeHtml(joinCode)}" autofocus>
<button id="btn" onclick="join()">Connect</button>
<div class="msg" id="msg"></div>
<a class="back" href="/">← Back to Dashboard</a>
</div>
<script>
const msg=document.getElementById('msg');
const btn=document.getElementById('btn');
const inp=document.getElementById('code');
inp.addEventListener('keydown',e=>{if(e.key==='Enter')join()});
${joinCode ? "setTimeout(join,300);" : ""}
async function join(){
  const code=inp.value.trim().toUpperCase();
  if(!code){msg.className='msg error';msg.textContent='Enter a join code';return}
  btn.disabled=true;msg.className='msg loading';msg.textContent='Connecting…';
  try{
    const did=localStorage.getItem('device_id')||crypto.randomUUID();
    localStorage.setItem('device_id',did);
    const r=await fetch('/api/staff-sessions/join',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({join_code:code,device_id:did})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Join failed');
    msg.className='msg success';
    const portalMap={judge:'/app/judge',marshal:'/app/marshal',scanner:'/app/checkin',announcer:'/app/announcer',chairman:'/app/chairman',dj:'/app/dj',videographer:'/app/videographer',deck_captain:'/app/deckcaptain',scrutineer:'/app/scrutineer',event_admin:'/app/events'};
    const portal=portalMap[d.role]||'/app/marshal';
    // Bug 1 fix: redirect to cloud PWA with eventbox param so the React app picks it up
    const pwaBase='https://dance-flow-control.lovable.app';
    const portalUrl=pwaBase+portal+'?eventId='+d.event_id+'&eventbox='+encodeURIComponent(location.origin);
    const localFallback=location.origin+'/staff/join?join='+code;
    // Fix 3: use textContent for dynamic values to prevent XSS
    msg.textContent='';
    var check=document.createElement('span');check.textContent='✅ Welcome, ';
    var nameEl=document.createElement('strong');nameEl.textContent=d.staff_name;
    var roleBadge=document.createElement('span');roleBadge.className='role-badge';roleBadge.textContent=d.role;
    msg.appendChild(check);msg.appendChild(nameEl);msg.appendChild(document.createTextNode('! '));msg.appendChild(roleBadge);
    msg.appendChild(document.createElement('br'));
    var link=document.createElement('a');link.href=portalUrl;link.textContent='Go to Portal →';
    link.style.cssText='display:inline-block;margin-top:1rem;padding:.6rem 1.5rem;border-radius:8px;background:#6366f1;color:#fff;text-decoration:none;font-weight:600';
    msg.appendChild(link);
    msg.appendChild(document.createElement('br'));
    var hint=document.createElement('span');hint.style.cssText='font-size:.75rem;color:#94a3b8;margin-top:.5rem;display:block';
    hint.textContent='If offline, open the app on your device and enter code: '+code;
    msg.appendChild(hint);
    // Store session data for local use
    localStorage.setItem('eventbox_staff_session',JSON.stringify(d));
    localStorage.setItem('eventbox_base_url',location.origin);
  }catch(e){msg.className='msg error';msg.textContent='❌ '+e.message;btn.disabled=false}
}
</script></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // GET /staff — Staff portal entry point
  if (url.pathname === "/staff" && req.method === "GET") {
    const joinCode = url.searchParams.get("join") || "";
    if (joinCode) {
      // Redirect to /staff/join with the code
      return Response.redirect(`${url.origin}/staff/join?join=${encodeURIComponent(joinCode)}`, 302);
    }
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Staff Portal</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);text-align:center}
h1{margin:0 0 .5rem;font-size:1.5rem;color:#fff}
.subtitle{color:#94a3b8;font-size:.85rem;margin-bottom:1.5rem}
input{width:100%;padding:.85rem;border-radius:8px;border:2px solid #334155;background:#0f172a;color:#fff;font-size:1.3rem;text-align:center;letter-spacing:.3em;margin:.75rem 0;outline:none;transition:border-color .2s}
input:focus{border-color:#6366f1}
button{width:100%;padding:.85rem;border-radius:8px;border:none;background:#6366f1;color:#fff;font-size:1rem;cursor:pointer;font-weight:600}
button:hover{background:#4f46e5}
.back{display:block;text-align:center;margin-top:1.5rem;color:#818cf8;font-size:.85rem;text-decoration:none}
.back:hover{text-decoration:underline}
</style></head>
<body><div class="card">
<h1>Staff Portal</h1>
<p class="subtitle">Enter the join code from your event admin</p>
<input id="code" placeholder="Join Code" maxlength="8" autofocus>
<button onclick="go()">Join</button>
<a class="back" href="/">← Back to Dashboard</a>
</div>
<script>
document.getElementById('code').addEventListener('keydown',e=>{if(e.key==='Enter')go()});
function go(){
  const code=document.getElementById('code').value.trim();
  if(!code)return;
  location.href='/staff/join?join='+encodeURIComponent(code);
}
</script></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
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

  // ---- /app/* catch-all: friendly redirect instead of 404 (Bug 1 fix) ----
  if (url.pathname.startsWith("/app/")) {
    const pwaBase = "https://dance-flow-control.lovable.app";
    const redirectUrl = pwaBase + url.pathname + url.search + (url.search ? "&" : "?") + "eventbox=" + encodeURIComponent(url.origin);
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EventBox — Open App</title>
<meta http-equiv="refresh" content="3;url=${escapeHtml(redirectUrl)}">
<style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;margin:0;min-height:100vh;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border-radius:16px;padding:2.5rem;max-width:400px;width:100%;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);text-align:center}
h1{margin:0 0 .5rem;font-size:1.5rem;color:#fff}
p{color:#94a3b8;font-size:.85rem;line-height:1.6}
a{color:#818cf8}
</style></head>
<body><div class="card">
<h1>Opening App…</h1>
<p>Redirecting you to the app. If it doesn't open automatically:</p>
<p><a href="${escapeHtml(redirectUrl)}">Open App →</a></p>
<p style="margin-top:1rem;font-size:.75rem">If you're offline, open the installed app on your device and enter your staff code there.</p>
</div></body></html>`;
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  return json({ error: "not found" }, 404);
});

console.log(`\n🎯 EventBox v0.3 running on port ${PORT}`);
console.log(`   Event:     ${EVENT_ID}`);
console.log(`   Room code: ${ROOM_CODE}`);
console.log(`   Database:  ${DB_PATH}`);
console.log(`   Auth:      HMAC-SHA256 tokens (${TOKEN_TTL_MS / 3600000}h TTL)\n`);
