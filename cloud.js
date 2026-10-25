'use strict';
// Cloud saves for Stock Idle. Zero dependencies (Node built-ins only).
//
//  - Sign-in: the browser gets a Google ID token (Google Identity Services). We verify its RS256 signature against
//    Google's public keys, check issuer / audience / expiry, then hand back our own signed session token (30 days).
//  - Storage: one folder per user under DATA_DIR (named by a SHA-256 of the Google account id; no email is stored):
//      users/<hash>/slot1.json .. slot3.json   { rev, at, data }
//      users/<hash>/ach.json                    all-time achievements merged across devices
//    On Railway attach a Volume and set DATA_DIR to its mount path (e.g. /data), otherwise saves vanish on redeploy.
//  - Leaderboard: public top lists for Classic and Live. Each signed-in player's entry is their highest net worth among their
//    current cloud slots of that mode. Net worth is recomputed on the server from the saved data (never sent by the client).
//    Display name is "First L." from Google; players can hide themselves (users/<hash>/profile.json).
//  - Conflicts: every slot has a revision number. A write must name the revision it was based on (baseRev);
//    if the cloud moved on in the meantime the server answers 409 and the game asks the player which copy to keep.
//
// Environment: GOOGLE_CLIENT_ID (required to enable), DATA_DIR, SESSION_SECRET (optional; generated and stored otherwise).
const fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');

const CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const CERTS = process.env.GOOGLE_CERTS_URL || 'https://www.googleapis.com/oauth2/v3/certs';
const SLOTS = 3, MAX_IN = 4 * 1024 * 1024, MAX_OUT = 24 * 1024 * 1024, SESSION_MS = 30 * 86400e3;
const enabled = !!CLIENT_ID;

try { fs.mkdirSync(path.join(DATA, 'users'), { recursive: true }); } catch (e) { console.log('Cannot create DATA_DIR ' + DATA + ': ' + e.message); }

let SECRET = (process.env.SESSION_SECRET || '').trim();
if (!SECRET) {
  const f = path.join(DATA, 'secret.key');
  try { SECRET = fs.readFileSync(f, 'utf8').trim(); } catch (e) {}
  if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); try { fs.writeFileSync(f, SECRET, { mode: 0o600 }); } catch (e) {} }
}

// ---------- small helpers ----------
const b64u = b => Buffer.from(b).toString('base64url');
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(sub) { const p = b64u(JSON.stringify({ s: sub, exp: Date.now() + SESSION_MS })); return p + '.' + hmac(p); }
function readToken(t) {
  const [p, sig] = String(t || '').split('.');
  if (!p || !sig) return null;
  const want = Buffer.from(hmac(p)), got = Buffer.from(sig);
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() && typeof o.s === 'string' ? o.s : null; } catch (e) { return null; }
}
const uid = sub => crypto.createHash('sha256').update(sub).digest('hex');
const udir = id => path.join(DATA, 'users', id);
const slotFile = (id, n) => path.join(udir(id), 'slot' + n + '.json');
function rj(f, d) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return d; } }
function wj(f, o) { fs.mkdirSync(path.dirname(f), { recursive: true }); const t = f + '.' + process.pid + '.tmp'; fs.writeFileSync(t, JSON.stringify(o)); fs.renameSync(t, f); }

// very small in-memory rate limiter
const hits = new Map();
function limited(key, max, ms) {
  const now = Date.now(); let h = hits.get(key);
  if (!h || now > h.r) { h = { n: 0, r: now + ms }; hits.set(key, h); }
  if (hits.size > 5000) for (const [k, v] of hits) if (now > v.r) hits.delete(k);
  return ++h.n > max;
}

function send(req, res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj)), h = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  if (body.length > 2048 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    h['Content-Encoding'] = 'gzip'; res.writeHead(status, h); return res.end(zlib.gzipSync(body));
  }
  res.writeHead(status, h); res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > MAX_IN) { reject(Object.assign(new Error('too large'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('error', reject);
    req.on('end', () => {
      try {
        let buf = Buffer.concat(chunks);
        if ((req.headers['content-encoding'] || '') === 'gzip') buf = zlib.gunzipSync(buf, { maxOutputLength: MAX_OUT });
        resolve(buf.length ? JSON.parse(buf.toString('utf8')) : {});
      } catch (e) { reject(Object.assign(new Error('bad body'), { code: 400 })); }
    });
  });
}

// ---------- Google ID token verification ----------
let jwks = { keys: [], at: 0 };
async function googleKey(kid) {
  if (!jwks.keys.find(k => k.kid === kid) && Date.now() - jwks.at > 60e3) {
    const r = await fetch(CERTS, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error('certs ' + r.status);
    const j = await r.json(); jwks = { keys: j.keys || [], at: Date.now() };
  }
  return jwks.keys.find(k => k.kid === kid);
}
async function verifyGoogle(cred) {
  const parts = String(cred || '').split('.');
  if (parts.length !== 3) throw new Error('malformed');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()), payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  if (header.alg !== 'RS256') throw new Error('alg');
  const jwk = await googleKey(header.kid);
  if (!jwk) throw new Error('unknown key');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new Error('signature');
  if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') throw new Error('issuer');
  if (payload.aud !== CLIENT_ID) throw new Error('audience');
  if (!(payload.exp * 1000 > Date.now())) throw new Error('expired');
  if (typeof payload.sub !== 'string' || !payload.sub) throw new Error('subject');
  return { sub: payload.sub, name: String(payload.name || payload.given_name || 'Player').slice(0, 80), picture: /^https:\/\//.test(payload.picture || '') ? String(payload.picture).slice(0, 400) : '' };
}

// ---------- leaderboard ----------
// In-memory index rebuilt from disk at startup, then updated whenever a slot is saved or deleted.
// board: id -> { name, hide, classic: {nw, at} | null, live: {nw, at} | null }
const board = new Map(), MODES = ['classic', 'live'];
let lbCache = { at: 0, v: null };
const num = v => (typeof v === 'number' && isFinite(v) ? v : 0);
function saveNW(o) { // same formula as the game's slotNW(), computed from the stored save
  if (!o || typeof o !== 'object' || !o.p || typeof o.p !== 'object') return 0;
  let t = num(o.cash);
  if (o.su && Array.isArray(o.su.list)) for (const l of o.su.list) t += num(l && l.n) * num(l && l.p);
  for (const k in (o.hold || {})) { const h = o.hold[k]; t += num(h && h.n) * num(o.p[k] && o.p[k].p); }
  for (const k in (o.priv || {})) t += num(o.priv[k] && o.priv[k].v);
  return t > 0 && t < 1e18 ? Math.round(t * 100) / 100 : 0;
}
function shortName(n) {
  const w = String(n || '').replace(/[\u0000-\u001f<>]/g, '').trim().split(/\s+/).filter(Boolean);
  if (!w.length) return 'Player';
  const f = w[0].slice(0, 20); return w.length > 1 ? f + ' ' + Array.from(w[w.length - 1])[0].toUpperCase() + '.' : f;
}
const profFile = id => path.join(udir(id), 'profile.json');
function reindex(id) {
  const pr = rj(profFile(id), {}), e = { name: pr.name || 'Player', hide: !!pr.hide, classic: null, live: null };
  for (let n = 1; n <= SLOTS; n++) {
    const s = rj(slotFile(id, n), null); if (!s || !s.data) continue;
    const nw = saveNW(s.data), m = s.data.mode === 'live' ? 'live' : 'classic';
    if (nw > 0 && (!e[m] || nw > e[m].nw)) e[m] = { nw, at: s.at || 0 };
  }
  if (e.classic || e.live) board.set(id, e); else board.delete(id);
  lbCache = { at: 0, v: null };
}
function buildBoard() {
  try { for (const id of fs.readdirSync(path.join(DATA, 'users'))) reindex(id); } catch (e) {}
}
function leaderboard(myId) {
  if (!lbCache.v || Date.now() - lbCache.at > 10e3) {
    const v = {};
    for (const m of MODES) v[m] = [...board].filter(([, e]) => e[m] && !e.hide).sort((a, b) => b[1][m].nw - a[1][m].nw || a[1][m].at - b[1][m].at);
    lbCache = { at: Date.now(), v };
  }
  const out = { ok: true };
  for (const m of MODES) {
    const l = lbCache.v[m];
    out[m] = l.slice(0, 10).map(([id, e], i) => ({ r: i + 1, name: e.name, nw: e[m].nw, you: id === myId }));
    out[m + 'Total'] = l.length;
    if (myId) { const i = l.findIndex(([id]) => id === myId); const mine = board.get(myId); out.me = out.me || {}; out.me[m] = i >= 0 ? { r: i + 1, nw: l[i][1][m].nw } : mine && mine[m] ? { r: 0, nw: mine[m].nw } : null; }
  }
  return out;
}
buildBoard();

// ---------- achievements merge (union, earliest unlock time wins; counters keep the highest) ----------
function mergeAch(a, b) {
  const o = { a: {}, trades: 0, ticks: 0, best: 0 };
  [a, b].forEach(x => {
    if (!x || typeof x !== 'object') return;
    for (const k in (x.a || {})) { const t = +x.a[k]; if (t > 0 && (!o.a[k] || t < o.a[k])) o.a[k] = t; }
    ['trades', 'ticks', 'best'].forEach(k => { const v = +x[k]; if (v > o[k]) o[k] = v; });
  });
  return o;
}

// ---------- achievement stats: how many players (with cloud saves) hold each achievement; cached 5 min ----------
let achCache = { at: 0, v: null };
function achStats() {
  if (achCache.v && Date.now() - achCache.at < 300e3) return achCache.v;
  const c = {}; let n = 0;
  try {
    for (const id of fs.readdirSync(path.join(DATA, 'users'))) {
      const x = rj(path.join(udir(id), 'ach.json'), null);
      if (!x || typeof x.a !== 'object') continue;
      n++;
      for (const k in x.a) if (+x.a[k] > 0) c[k] = (c[k] || 0) + 1;
    }
  } catch (e) {}
  achCache = { at: Date.now(), v: { ok: true, n, c } };
  return achCache.v;
}

// ---------- routes ----------
async function route(req, res, p) {
  const m = req.method, ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (p === '/api/config' && m === 'GET') return send(req, res, 200, { cloud: enabled, clientId: enabled ? CLIENT_ID : '', slots: SLOTS });
  if (!enabled) return send(req, res, 503, { ok: false, error: 'disabled' });

  if (p === '/api/auth/google') {
    if (m !== 'POST') return send(req, res, 405, { ok: false });
    if (limited('a:' + ip, 20, 60e3)) return send(req, res, 429, { ok: false, error: 'slow down' });
    const b = await readJson(req);
    let u;
    try { u = await verifyGoogle(b.credential); } catch (e) { return send(req, res, 401, { ok: false, error: 'invalid sign-in' }); }
    { const id0 = uid(u.sub), pf = rj(profFile(id0), {}); try { wj(profFile(id0), { name: shortName(u.name), hide: !!pf.hide }); reindex(id0); } catch (e) {} }
    return send(req, res, 200, { ok: true, token: makeToken(u.sub), user: { name: u.name, picture: u.picture } });
  }

  if (p === '/api/leaderboard' && m === 'GET') {
    if (limited('l:' + ip, 60, 60e3)) return send(req, res, 429, { ok: false, error: 'slow down' });
    const s0 = readToken((req.headers.authorization || '').replace(/^Bearer /i, ''));
    return send(req, res, 200, leaderboard(s0 ? uid(s0) : ''));
  }

  if (p === '/api/ach-stats' && m === 'GET') {
    if (limited('s:' + ip, 60, 60e3)) return send(req, res, 429, { ok: false, error: 'slow down' });
    return send(req, res, 200, achStats());
  }

  const sub = readToken((req.headers.authorization || '').replace(/^Bearer /i, ''));
  if (!sub) return send(req, res, 401, { ok: false, error: 'unauthorized' });
  const id = uid(sub);
  if (limited('u:' + id, 120, 60e3)) return send(req, res, 429, { ok: false, error: 'slow down' });

  if (p === '/api/saves' && m === 'GET') {
    const slots = {};
    for (let n = 1; n <= SLOTS; n++) { const s = rj(slotFile(id, n), null); if (s && s.data) slots[n] = s; }
    return send(req, res, 200, { ok: true, hide: !!rj(profFile(id), {}).hide, slots, ach: rj(path.join(udir(id), 'ach.json'), { a: {}, trades: 0, ticks: 0, best: 0 }) });
  }
  let mm = /^\/api\/saves\/(\d+)$/.exec(p);
  if (mm) {
    const n = +mm[1]; if (n < 1 || n > SLOTS) return send(req, res, 400, { ok: false, error: 'bad slot' });
    const f = slotFile(id, n), cur = rj(f, null), rev = cur ? cur.rev : 0;
    if (m === 'PUT') {
      const b = await readJson(req), d = b.data;
      if (!d || typeof d !== 'object' || Array.isArray(d) || !d.p || typeof d.p !== 'object') return send(req, res, 400, { ok: false, error: 'bad save' });
      if ((+b.baseRev || 0) !== rev) return send(req, res, 409, { ok: false, error: 'conflict', rev, at: cur ? cur.at : 0 });
      const rec = { rev: rev + 1, at: Date.now(), data: d };
      wj(f, rec); reindex(id);
      return send(req, res, 200, { ok: true, rev: rec.rev, at: rec.at });
    }
    if (m === 'DELETE') { try { fs.unlinkSync(f); } catch (e) {} reindex(id); return send(req, res, 200, { ok: true }); }
    return send(req, res, 405, { ok: false });
  }
  if (p === '/api/ach' && m === 'PUT') {
    const b = await readJson(req), f = path.join(udir(id), 'ach.json'), merged = mergeAch(rj(f, null), b.ach);
    wj(f, merged); return send(req, res, 200, { ok: true, ach: merged });
  }
  if (p === '/api/profile' && m === 'PUT') {
    const b = await readJson(req), pf = rj(profFile(id), {});
    wj(profFile(id), { name: pf.name || 'Player', hide: !!b.hide }); reindex(id);
    return send(req, res, 200, { ok: true, hide: !!b.hide });
  }
  if (p === '/api/account' && m === 'DELETE') {
    try { fs.rmSync(udir(id), { recursive: true, force: true }); } catch (e) {}
    board.delete(id); lbCache = { at: 0, v: null };
    return send(req, res, 200, { ok: true });
  }
  return send(req, res, 404, { ok: false });
}

const PATHS = /^\/api\/(config|auth\/google|saves(\/\d+)?|ach|account|leaderboard|profile)$/;
function handle(req, res, p) {
  if (!PATHS.test(p)) return false;
  route(req, res, p).catch(e => {
    if (!res.headersSent) send(req, res, e && e.code === 413 ? 413 : e && e.code === 400 ? 400 : 500, { ok: false, error: e && e.code ? e.message : 'server error' });
    if (!e || !e.code) console.log('cloud error: ' + (e && e.stack || e));
  });
  return true;
}

module.exports = { handle, enabled, DATA, mergeAch };
