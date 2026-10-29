// Aeon Tap: dynamic QR redirect + password-protected admin API (Cloudflare Worker + KV)
const enc = new TextEncoder();
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function pbk(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
async function mkCfg(pw) { const salt = rnd(16); return { salt, hash: await pbk(pw, salt), secret: rnd(32) }; }
// Password is stored hashed in KV (key "cfg"). ADMIN_PASSWORD is only used the first time.
async function getCfg(env) {
  let c = await env.LINKS.get('cfg', { type: 'json' });
  if (!c && env.ADMIN_PASSWORD) { c = await mkCfg(env.ADMIN_PASSWORD); await env.LINKS.put('cfg', JSON.stringify(c)); }
  return c;
}
async function sign(cfg, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(cfg.secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function authed(req, cfg) {
  const [ts, sig] = (req.headers.get('Authorization') || '').replace('Bearer ', '').split('.');
  if (!ts || !sig || !cfg || Date.now() - Number(ts) > 12 * 36e5) return false;
  return same(sig, await sign(cfg, 's' + ts));
}
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const okUrl = u => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:'; } catch { return false; } };
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const TYPES = ['Google review', 'Business card', 'Other'];
const RESERVED = ['ADMIN', 'INDEX'];

export default {
  async fetch(req, env) {
    const p = new URL(req.url).pathname;

    if (p.startsWith('/api/')) {
      const cfg = await getCfg(env);
      if (p === '/api/login' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        await new Promise(r => setTimeout(r, 500)); // slows password guessing
        if (!cfg || !same(await pbk(String(b.password || ''), cfg.salt), cfg.hash)) return J({ error: 'Wrong password' }, 401);
        const ts = String(Date.now());
        return J({ token: ts + '.' + await sign(cfg, 's' + ts) });
      }
      if (!await authed(req, cfg)) return J({ error: 'Session expired. Log in again.' }, 401);
      if (p === '/api/password' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        if (!same(await pbk(String(b.current || ''), cfg.salt), cfg.hash)) return J({ error: 'Current password is wrong' }, 403);
        if (String(b.next || '').length < 8) return J({ error: 'Use at least 8 characters' }, 400);
        const n = await mkCfg(String(b.next)); await env.LINKS.put('cfg', JSON.stringify(n));
        const ts = String(Date.now());
        return J({ token: ts + '.' + await sign(n, 's' + ts) });
      }
      const m = p.match(/^\/api\/links(?:\/([A-Z0-9]{3,12}))?$/);
      if (!m) return J({ error: 'Not found' }, 404);
      const code = m[1];
      const body = ['POST', 'PUT'].includes(req.method) ? await req.json().catch(() => ({})) : {};
      if (req.method === 'GET' && !code) {
        const l = await env.LINKS.list({ prefix: 'l:' });
        const out = await Promise.all(l.keys.map(async k => ({ code: k.name.slice(2), ...JSON.parse(await env.LINKS.get(k.name)) })));
        return J(out.sort((a, b) => (a.created || 0) - (b.created || 0)));
      }
      if (req.method === 'DELETE' && code) { await env.LINKS.delete('l:' + code); return J({ ok: true }); }
      if (req.method === 'POST' || req.method === 'PUT') {
        if (!okUrl(body.url)) return J({ error: 'Enter a full link starting with https://' }, 400);
        const rec = { label: String(body.label || 'Untitled').slice(0, 80), type: TYPES.includes(body.type) ? body.type : 'Other', url: body.url };
        if (req.method === 'PUT' && code) {
          const old = await env.LINKS.get('l:' + code);
          if (!old) return J({ error: 'Not found' }, 404);
          await env.LINKS.put('l:' + code, JSON.stringify({ ...rec, created: JSON.parse(old).created }));
          return J({ code, ...rec });
        }
        let c = String(body.code || '').toUpperCase();
        if (c) {
          if (!/^[A-Z0-9]{3,12}$/.test(c) || RESERVED.includes(c)) return J({ error: 'Code: 3 to 12 letters or numbers, not ADMIN or INDEX' }, 400);
          if (await env.LINKS.get('l:' + c)) return J({ error: 'That code is already used' }, 409);
        } else {
          do { c = Array.from({ length: 6 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join(''); } while (await env.LINKS.get('l:' + c));
        }
        await env.LINKS.put('l:' + c, JSON.stringify({ ...rec, created: Date.now() }));
        return J({ code: c, ...rec }, 201);
      }
      return J({ error: 'Bad request' }, 400);
    }

    // Scan: /KPA70Z -> redirect to the current link
    const m = p.match(/^\/([A-Za-z0-9]{3,12})\/?$/);
    if (m) {
      const v = await env.LINKS.get('l:' + m[1].toUpperCase());
      if (v) return new Response(null, { status: 302, headers: { Location: JSON.parse(v).url, 'cache-control': 'no-store' } });
    }
    return env.ASSETS.fetch(req);
  }
};
