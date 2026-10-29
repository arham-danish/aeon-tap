// Aeon Tap self-hosted server. No dependencies, Node 18+. Run: ADMIN_PASSWORD=yourpassword node server.js
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const PORT = process.env.PORT || 3000, PW = process.env.ADMIN_PASSWORD;
const DIR = path.dirname(fileURLToPath(import.meta.url)), PUB = path.join(DIR, 'public');
const DB = path.join(process.env.DATA_DIR || path.join(DIR, 'data'), 'links.json');
fs.mkdirSync(path.dirname(DB), { recursive: true });
let links = {}; try { links = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch {}
const save = () => { fs.writeFileSync(DB + '.tmp', JSON.stringify(links, null, 1)); fs.renameSync(DB + '.tmp', DB); };
const sign = m => crypto.createHmac('sha256', cfg.secret).update(m).digest('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const authed = req => { const [ts, sig] = (req.headers.authorization || '').replace('Bearer ', '').split('.'); return !!(ts && sig && Date.now() - Number(ts) < 12 * 36e5 && same(sig, sign('s' + ts))); };
// Password is stored hashed in data/config.json. ADMIN_PASSWORD is only used the first time (or to reset: delete config.json).
const CFG = path.join(path.dirname(DB), 'config.json');
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const mkCfg = pw => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPw(pw, salt), secret: crypto.randomBytes(32).toString('hex') }; };
const saveCfg = () => { fs.writeFileSync(CFG + '.tmp', JSON.stringify(cfg), { mode: 0o600 }); fs.renameSync(CFG + '.tmp', CFG); };
let cfg; try { cfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch {}
if (!cfg) { if (!PW || PW.length < 8) { console.error('First run: set ADMIN_PASSWORD (8+ characters), for example ADMIN_PASSWORD="your-password" node server.js'); process.exit(1); } cfg = mkCfg(PW); saveCfg(); }
const checkPw = pw => same(hashPw(String(pw || ''), cfg.salt), cfg.hash);
const okUrl = u => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:'; } catch { return false; } };
const send = (res, s, o) => { res.writeHead(s, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };
const body = req => new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e5) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.css': 'text/css', '.ico': 'image/x-icon' };
const TYPES = ['Google review', 'Business card', 'Other'], RESERVED = ['ADMIN', 'INDEX'], ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const fails = new Map();

http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  try {
    if (p === '/api/login' && req.method === 'POST') {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress, f = fails.get(ip) || { n: 0, t: 0 };
      if (f.n >= 5 && Date.now() - f.t < 60000) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
      const b = await body(req);
      if (!checkPw(b.password)) { fails.set(ip, { n: f.n + 1, t: Date.now() }); return send(res, 401, { error: 'Wrong password' }); }
      fails.delete(ip); const ts = String(Date.now());
      return send(res, 200, { token: ts + '.' + sign('s' + ts) });
    }
    if (p.startsWith('/api/')) {
      if (!authed(req)) return send(res, 401, { error: 'Session expired. Log in again.' });
      if (p === '/api/password' && req.method === 'POST') {
        const b = await body(req);
        if (!checkPw(b.current)) return send(res, 403, { error: 'Current password is wrong' });
        if (String(b.next || '').length < 8) return send(res, 400, { error: 'Use at least 8 characters' });
        cfg = mkCfg(String(b.next)); saveCfg(); const ts = String(Date.now());
        return send(res, 200, { token: ts + '.' + sign('s' + ts) });
      }
      const m = p.match(/^\/api\/links(?:\/([A-Z0-9]{3,12}))?$/); if (!m) return send(res, 404, { error: 'Not found' });
      const code = m[1];
      if (req.method === 'GET' && !code) return send(res, 200, Object.entries(links).map(([c, v]) => ({ code: c, ...v })).sort((a, b) => a.created - b.created));
      if (req.method === 'DELETE' && code) { delete links[code]; save(); return send(res, 200, { ok: true }); }
      if (req.method === 'POST' || req.method === 'PUT') {
        const b = await body(req);
        if (!okUrl(b.url)) return send(res, 400, { error: 'Enter a full link starting with https://' });
        const rec = { label: String(b.label || 'Untitled').slice(0, 80), type: TYPES.includes(b.type) ? b.type : 'Other', url: b.url };
        if (req.method === 'PUT' && code) {
          if (!links[code]) return send(res, 404, { error: 'Not found' });
          links[code] = { ...rec, created: links[code].created }; save(); return send(res, 200, { code, ...rec });
        }
        let c = String(b.code || '').toUpperCase();
        if (c) {
          if (!/^[A-Z0-9]{3,12}$/.test(c) || RESERVED.includes(c)) return send(res, 400, { error: 'Code: 3 to 12 letters or numbers, not ADMIN or INDEX' });
          if (links[c]) return send(res, 409, { error: 'That code is already used' });
        } else { do { c = Array.from({ length: 6 }, () => ALPHA[crypto.randomInt(ALPHA.length)]).join(''); } while (links[c]); }
        links[c] = { ...rec, created: Date.now() }; save(); return send(res, 201, { code: c, ...rec });
      }
      return send(res, 400, { error: 'Bad request' });
    }
    const f = p === '/' ? 'index.html' : p === '/admin' ? 'admin.html' : p.slice(1), full = path.join(PUB, f);
    if (full.startsWith(PUB + path.sep) && fs.existsSync(full) && fs.statSync(full).isFile()) {
      res.writeHead(200, { 'content-type': MIME[path.extname(full)] || 'application/octet-stream', 'x-content-type-options': 'nosniff' });
      return res.end(fs.readFileSync(full));
    }
    const m = p.match(/^\/([A-Za-z0-9]{3,12})\/?$/), v = m && links[m[1].toUpperCase()];
    if (v) { res.writeHead(302, { Location: v.url, 'cache-control': 'no-store' }); return res.end(); }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found');
  } catch (e) { console.error(e); send(res, 500, { error: 'Server error' }); }
}).listen(PORT, () => console.log('Aeon Tap running on http://localhost:' + PORT + '  (admin: /admin)'));
