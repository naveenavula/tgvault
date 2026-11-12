# TGVault

Chrome / Edge extension that stores photos and files in your own **Telegram Saved Messages**, end-to-end encrypted in the browser.

- Logs in with your Telegram account (MTProto via [GramJS](https://github.com/gram-js/gramjs)); stays signed in until you log out
- Files, names, types and folder names are encrypted client-side (PBKDF2-SHA256 → HKDF → AES-256-GCM, chunked, tamper/truncation-proof)
- Folders, search, preview, drag & drop, live sync with Saved Messages
- Share any file as a single password-locked `.html` file (AES-256-GCM, opens in any browser, ≤150 MB)

## Setup
1. Register a Telegram app at https://my.telegram.org/apps and put the values in `static/credentials.json`:
   ```json
   { "api_id": "1234567", "api_hash": "0123456789abcdef0123456789abcdef" }
   ```
   **Do not commit your real `api_hash` to a public repo.**
2. Build (Node 18+):
   ```
   npm install
   npm run build
   ```
3. Open `chrome://extensions` (or `edge://extensions`), enable Developer mode, **Load unpacked**, choose the `dist/` folder.

## Security notes
- Your encryption passphrase cannot be recovered. Use the same passphrase on every device.
- The design uses standard Web Crypto primitives but has **not been independently audited**.
- The Telegram session is kept in `chrome.storage.local` (unencrypted) until you log out.
- Crypto lives in `src/crypto.js` (vault) and `src/share.js` (share files). `npm test` runs round-trip and tamper tests.
