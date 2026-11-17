# TGVault

Chrome / Edge extension that stores photos and files in your own **Telegram Saved Messages**, end-to-end encrypted in the browser.

- Logs in with your Telegram account (MTProto via [GramJS](https://github.com/gram-js/gramjs)); stays signed in until you log out
- Asks for your passphrase each time the browser is restarted (and after **Lock**); the saved Telegram login is encrypted with it
- Large downloads (64 MB+) are written straight to a file you choose instead of being held in memory
- Files, names, types and folder names are encrypted client-side (PBKDF2-SHA256 → HKDF → AES-256-GCM, chunked, tamper/truncation-proof)
- Folders, search, preview, drag & drop, live sync with Saved Messages
- Upload whole folders (button or drag & drop) — subfolders are recreated inside the vault
- Select many files (checkbox, Ctrl/⌘-click, Shift-click for a range) to move or delete them together; move whole folders with **Move** or by dragging them onto another folder or the path bar
- Share any file as a single password-locked `.html` file (AES-256-GCM, opens in any browser, ≤150 MB)

## Install (no Node/npm needed)
1. Download this repo (**Code → Download ZIP**) and unzip it.
2. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode**.
3. Click **Load unpacked** and choose the **`extension`** folder (the one that directly contains `manifest.json`).
4. Put your Telegram app credentials in `extension/credentials.json` (free, from https://my.telegram.org/apps), then click the reload arrow on the extension:
   ```json
   { "api_id": "1234567", "api_hash": "0123456789abcdef0123456789abcdef" }
   ```
5. Click the TGVault icon, log in with your phone number and code, and create your encryption passphrase.

## Build from source (optional, needs Node 18+)
```
npm install
npm run build        # outputs dist/
```

## Security notes
- Your encryption passphrase cannot be recovered. Use the same passphrase on every device.
- The design uses standard Web Crypto primitives but has **not been independently audited**.
- The Telegram session is kept in `chrome.storage.local` **encrypted with your passphrase key**. The key itself lives only in browser memory (`chrome.storage.session`), so nothing on disk can open the vault or the Telegram login. While the browser is open and the vault is unlocked, the key is in memory — click **Lock** when you are done.
- File and folder names are stored in the Telegram caption (1024-character limit). Very long names are shortened (the extension is kept) and folder paths are limited to 400 bytes.
- Crypto lives in `src/crypto.js` (vault) and `src/share.js` (share files). `npm test` runs round-trip and tamper tests.
