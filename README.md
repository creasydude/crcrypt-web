# CRCrypt Web

Offline, zero‑persistence AES‑256‑CBC (default) PWA with optional AES‑256‑GCM. This guide deploys the static site to Cloudflare Pages using Wrangler v3.

Prerequisites
- Cloudflare account with Pages enabled
- Node.js 18+
- Wrangler v3: npm i -g wrangler

Project structure
- index.html
- styles.css
- manifest.webmanifest
- sw.js
- src/ui.js
- src/crypto.js
- src/utils/hex.js
- _headers (security headers for Pages)

Security headers
- CSP, COOP, etc. are defined via _headers and reinforced in index.html.
- Service-Worker-Allowed: / for sw.js scope.

Deploy steps
1) Login: wrangler login
2) Create the Pages project (one-time): wrangler pages project create crcrypt-web
3) Publish the current directory: wrangler pages deploy . --project-name=crcrypt-web --branch=production


Local development with Pages
- Run dev server: wrangler pages dev .
- Open https://localhost:8788 (default).

Notes on SW and caching
- SW is registered from src/ui.js and will pre-cache static assets.
- _headers sets no-cache for index.html, sw.js, manifest.webmanifest to ensure updates propagate.
- Only static assets are cached; no runtime data is stored.

Zero‑persistence guarantee
- No localStorage/sessionStorage/IndexedDB.
- No network calls beyond serving static assets.
- Clipboard only on explicit user action.
- Memory zeroization of buffers after crypto operations.

Compatibility with CLI
- Output (AES‑256‑CBC default): hex salt:iv:ciphertext
- Output (AES‑256‑GCM supported): hex salt:iv:ciphertext:tag
- Defaults: AES‑256‑CBC, PBKDF2‑SHA256 100k iterations, salt 32 bytes, IV 16 bytes, key 32 bytes.
- Adjust salt/iv/iterations/key via Advanced Settings.

Updating the site
- Edit files and re‑publish: wrangler pages publish . --project-name=crcrypt-web
- SW changes may take a refresh+hard reload to take effect.

Custom domain (optional)
- Attach your domain to the Pages project in Cloudflare dashboard.
- HTTPS is automatic; SW works under HTTPS.

Troubleshooting
- If SW not registering, ensure HTTPS or localhost and Service-Worker-Allowed header on /sw.js.
- If CSP blocks, verify _headers is present at project root and no external scripts/styles are used.
- If pages publish fails, check wrangler login and project name.

Commands (copy/paste)
- npm i -g wrangler
- wrangler login
- wrangler pages project create crcrypt-web
- wrangler pages dev .
- wrangler pages publish . --project-name=crcrypt-web

This repository is static; no build step required.

Security reminder
- Keep your password secret; encryption is local and non‑recoverable without the correct password.