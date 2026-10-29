# Aeon Tap: website + dynamic QR dashboard

Your website, your dashboard, your data. Anyone with the admin password can log in at /admin, add QR links and change where existing QR codes point. Nothing here depends on any outside service: no third-party scripts, fonts or logins.

## How it works
Each QR or NFC tag holds https://yourdomain/CODE. When it is scanned, the server looks up CODE and redirects to the current link. Change the link in /admin and the same printed code goes to the new place.

## Passwords
The first password comes from ADMIN_PASSWORD. After that, change it any time inside the dashboard (Change password button). It is stored hashed, never in plain text.
Forgot it? Option A: delete data/config.json, then start again with ADMIN_PASSWORD="new-password" node server.js. Option B: in the Cloudflare dashboard open Workers KV, your LINKS namespace, delete the key named cfg, then log in with the ADMIN_PASSWORD secret.

## Option B: Cloudflare (recommended: free plan, nothing to keep running)
Your data stays under your own Cloudflare login. Needs Node.js. Run these in the aeon-tap-server folder:
1. npx wrangler login   (opens the browser; create a free Cloudflare account if you do not have one)
2. npx wrangler kv namespace create LINKS   (prints an id; paste it into wrangler.toml in place of PASTE_YOUR_KV_ID_HERE; if it offers to edit the config for you, say no)
3. npx wrangler deploy   (prints your address, https://aeon-tap.YOURNAME.workers.dev)
4. npx wrangler secret put ADMIN_PASSWORD   (type your first password when asked)
5. Open your address followed by /admin and log in.
To use your own domain: add the domain to Cloudflare, then Workers & Pages > aeon-tap > Settings > Domains & Routes > Add > Custom domain.
Cloudflare free plan limits have changed over time, so check cloudflare.com for the current numbers. Scans are cheap reads and normally fit easily.
After editing any file, run npx wrangler deploy again.

## Option A: run it on your own server
Needs Node.js 18 or newer. No packages to install.

    ADMIN_PASSWORD="choose-a-long-password" node server.js

Windows (PowerShell):

    $env:ADMIN_PASSWORD="choose-a-long-password"; node server.js

Open http://localhost:3000 and http://localhost:3000/admin. Links are stored in data/links.json and the password hash in data/config.json (back up the data folder).
To be reachable from phones it needs an always-on machine with HTTPS and a domain: a spare PC or Raspberry Pi with Cloudflare Tunnel (free), or a free cloud VM such as Oracle Cloud Always Free. Avoid hosts whose free plan puts the app to sleep, because scans would fail while it sleeps.

## Before you print anything
Use your own domain, never a temporary address, so printed codes stay valid for good.
