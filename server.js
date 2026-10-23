// Zero-dependency server (works on Railway, which provides PORT).
// Serves the game and, for the "Live Market" mode, a small cached proxy for real stock quotes.
//
// Live quotes come from Finnhub (https://finnhub.io, free API key). Set it as an environment variable:
//   FINNHUB_API_KEY=your_key node server.js
// The key stays on the server and is never sent to the browser. All players share one cache, so the
// free tier (60 calls/min) is enough: the server refreshes about 1 symbol per 1.1 seconds, and only
// while somebody is actually playing a Live game.
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const PUB = path.join(__dirname, 'public');
const TYPES = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css',
  '.json':'application/json', '.svg':'image/svg+xml', '.png':'image/png', '.ico':'image/x-icon' };

const KEY = (process.env.FINNHUB_API_KEY || '').trim(); // never hardcode this: set it in Railway -> Variables
const BASE = process.env.FINNHUB_BASE || 'https://finnhub.io/api/v1';
// Game ticker -> real ticker, where they differ (GLD and BND are the same in both).
const MAP = { IDX:'SPY', TECH:'QQQ', DIV:'SCHD', BRKB:'BRK.B', SQ:'XYZ' };
// Fictional or unpriceable in this mode: Starlink is a SpaceX subsidiary (not listed), crypto is not supported yet.
const NOQUOTE = new Set(['STRL','BTC','ETH','SOL','DOGE']);

const CACHE_FILE = path.join(os.tmpdir(), 'idle-stocks-quotes.json');
let cache = {};                       // game ticker -> { c, pc, t, at, none? }
try { cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')) || {}; } catch (e) {}
const want = new Map();               // game ticker -> last time a player asked for it
let hot = new Set(), lastReq = 0, backoff = 0, n = 0, dirty = false, authErr = 0;

async function pollOne() {
  const now = Date.now();
  if (!KEY || now < backoff || now - lastReq > 5 * 60e3) return;   // idle when nobody is playing Live
  const syms = [...want.keys()].filter(s => now - want.get(s) < 5 * 60e3);
  if (!syms.length) return;
  const age = s => { const q = cache[s]; return !q ? 0 : q.none ? q.at + 3600e3 : q.at; }; // never fetched first; unpriceable ones retried hourly
  const pool = (n++ % 3 === 0 && [...hot].some(s => syms.includes(s))) ? syms.filter(s => hot.has(s)) : syms;
  const sym = pool.reduce((a, b) => age(b) < age(a) ? b : a);
  try {
    const r = await fetch(BASE + '/quote?symbol=' + encodeURIComponent(MAP[sym] || sym) + '&token=' + KEY, { signal: AbortSignal.timeout(8000) });
    if (r.status === 429) { backoff = Date.now() + 20000; return; }
    if (r.status === 401 || r.status === 403) { authErr = r.status; backoff = Date.now() + 15000; console.log('Finnhub rejected the API key (HTTP ' + r.status + '). Check FINNHUB_API_KEY.'); return; } // bad key: do NOT mark stocks as unpriceable
    if (!r.ok) { cache[sym] = { c: 0, pc: 0, t: 0, at: Date.now(), none: true }; return; }
    authErr = 0;
    const j = await r.json();
    cache[sym] = j && j.c > 0 ? { c: j.c, pc: j.pc || j.c, t: j.t || 0, at: Date.now() } : { c: 0, pc: 0, t: 0, at: Date.now(), none: true };
    dirty = true;
  } catch (e) { backoff = Date.now() + 5000; }
}
setInterval(pollOne, +process.env.POLL_MS || 1100);
setInterval(() => { if (dirty) { dirty = false; try { fs.writeFileSync(CACHE_FILE, JSON.stringify(cache)); } catch (e) {} } }, 30000);

function quotes(req, res) {
  const u = new URL(req.url, 'http://x');
  const ok = s => /^[A-Z0-9]{1,6}$/.test(s) && !NOQUOTE.has(s);
  const s = (u.searchParams.get('s') || '').split(',').filter(ok).slice(0, 150);
  const h = (u.searchParams.get('h') || '').split(',').filter(ok).slice(0, 50);
  const now = Date.now(); lastReq = now; hot = new Set(h);
  s.forEach(x => want.set(x, now));
  const out = {}; let ready = 0;
  s.forEach(x => { const q = cache[x]; if (q && q.c > 0) { out[x] = { c: q.c, pc: q.pc, t: q.t }; ready++; } });
  const body = !KEY ? { ok: false, error: 'nokey', now, quotes: {} }
    : (authErr && !ready) ? { ok: false, error: 'badkey', now, quotes: {} }
    : { ok: true, now, total: s.length, ready, quotes: out };
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/api/quotes') return quotes(req, res);
  if (p === '/') p = '/index.html';
  const f = path.normalize(path.join(PUB, p));
  if (!f.startsWith(PUB)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' });
    res.end(d);
  });
}).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Running on ' + (process.env.PORT || 3000) + (KEY ? '' : ' (no FINNHUB_API_KEY set: Live Market mode is disabled)')));
