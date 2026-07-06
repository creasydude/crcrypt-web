<div align="center">

# 🔐 CRCrypt

**Offline, zero-persistence AES-256 encryption/decryption in your browser.**

Your data never leaves your device. No network calls. No storage. No traces.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PWA Ready](https://img.shields.io/badge/PWA-Ready-5A0DC8.svg)](manifest.webmanifest)
[![Cloudflare Pages](https://img.shields.io/badge/Deploy-Cloudflare%20Pages-F48120.svg)](#-deploy-to-cloudflare-pages)
[![Zero Persistence](https://img.shields.io/badge/Data-Zero%20Persistence-brightgreen.svg)](#-zero-persistence-guarantee)

</div>

---

## Features

- **AES-256-CBC** (default) and **AES-256-GCM** encryption
- **PBKDF2-SHA256** key derivation with configurable iterations
- **Offline-first** — works without internet after first load
- **Zero persistence** — no localStorage, sessionStorage, or IndexedDB
- **PWA** — installable as a standalone app
- **Dark/Light theme** with system preference detection
- **Responsive** — works on desktop, tablet, and mobile
- **CLI compatible** — output format matches the CRCrypt CLI tool

## Quick Start

### Run Locally

```bash
# Option 1: Python (no install needed)
python3 -m http.server 8080
# Open http://localhost:8080

# Option 2: Node.js
npx serve .
# Open http://localhost:3000

# Option 3: With Wrangler (Cloudflare Pages dev)
npx wrangler pages dev .
# Open http://localhost:8788
```

### Install Wrangler (optional)

```bash
npm install -g wrangler
```

## Deploy to Cloudflare Pages

### One-time Setup

```bash
# Login to Cloudflare
wrangler login

# Create the Pages project
wrangler pages project create crcrypt-web
```

### Deploy

```bash
# Deploy to production
wrangler pages deploy . --project-name=crcrypt-web --branch=production

# Deploy to preview
wrangler pages deploy . --project-name=crcrypt-web --branch=preview
```

### Custom Domain

1. Go to your Cloudflare Pages project dashboard
2. Navigate to **Custom Domains**
3. Add your domain and follow the DNS verification steps
4. HTTPS is automatically provisioned

## Project Structure

```
crcrypt-web/
├── index.html              # App shell (single-page)
├── styles.css              # Premium dark design system
├── manifest.webmanifest    # PWA manifest
├── sw.js                   # Service worker for offline
├── _headers                # Security headers (CSP, COOP, etc.)
├── _redirects              # Cloudflare Pages redirects
└── src/
    ├── ui.js               # UI logic and interactions
    ├── crypto.js           # Web Crypto API operations
    └── utils/
        └── hex.js          # Hex encoding utilities
```

## How It Works

### Encryption Flow

1. **Key Derivation**: Password → PBKDF2-SHA256 → AES key (configurable iterations)
2. **Encryption**: Plaintext + key → AES-CBC/GCM → Ciphertext
3. **Output Format**: `hex(salt):hex(iv):hex(ciphertext)` (or `:hex(tag)` for GCM)

### Decryption Flow

1. **Parse**: Split input into salt, IV, ciphertext (and tag for GCM)
2. **Auto-detect**: Algorithm inferred from format (3 parts = CBC, 4 parts = GCM)
3. **Key Derivation**: Password + salt → PBKDF2 → AES key
4. **Decrypt**: Ciphertext + key → Plaintext

### Default Settings

| Parameter | Default | Range |
|-----------|---------|-------|
| Algorithm | AES-256-CBC | AES-128/192/256-CBC/GCM |
| PBKDF2 Iterations | 100,000 | 10,000–1,000,000 |
| Salt Length | 32 bytes | 16–64 bytes |
| IV Length | 16 bytes (CBC) / 12 bytes (GCM) | Fixed per algorithm |
| Key Length | 32 bytes (256-bit) | 16/24/32 bytes |

## CLI Compatibility

Output from CRCrypt Web is compatible with the CRCrypt CLI tool:

```bash
# Encrypt with CLI
echo "secret" | crcrypt encrypt -p "mypassword"

# Decrypt in browser — paste the output and enter the same password
```

## Security

- **No data persistence**: All encryption/decryption happens in memory only
- **Web Crypto API**: Uses browser-native cryptographic operations
- **PBKDF2**: Industry-standard key derivation with configurable work factor
- **Zero network calls**: No analytics, no telemetry, no external requests
- **CSP headers**: Strict Content-Security-Policy via `_headers`

## Accessibility

- WCAG AA contrast ratios
- Keyboard navigation support
- Screen reader compatible with ARIA labels
- Respects `prefers-reduced-motion`
- Focus visible states on all interactive elements

## Browser Support

| Browser | Status |
|---------|--------|
| Chrome 63+ | ✅ Full support |
| Firefox 57+ | ✅ Full support |
| Safari 11+ | ✅ Full support |
| Edge 79+ | ✅ Full support |

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ❤️ for privacy-first encryption**

</div>
