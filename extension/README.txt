TGVault – encrypted photo & file storage on Telegram Saved Messages

INSTALL (no Node/npm needed)
 1. Unzip this folder somewhere permanent (Chrome loads it from disk; don't delete it).
 2. Open chrome://extensions, switch on "Developer mode" (top right).
 3. Click "Load unpacked" and choose this folder.
 4. Click the TGVault icon (pin it from the puzzle-piece menu).
 5. First run: log in with your phone number + code (+ 2FA password if set), then create an encryption passphrase.

ONE-TIME CONFIG (done once by whoever builds/distributes it)
 Telegram requires every app to have its own api_id/api_hash (free, https://my.telegram.org/apps).
 Put them in credentials.json in this folder before loading. If they're present, users never see them.

NOTES
 - Keep the TGVault tab open while uploads/downloads run.
 - "Upload folder" (or dragging a folder in) keeps its subfolders. Empty folders are kept only when dragged in.
 - Tick files (or Ctrl/Cmd-click, Shift-click for a range) to move or delete many at once; drag files or folders onto a folder or the path bar to move them.
 - The passphrase cannot be recovered. Use the same one on every device.
 - You are asked for the passphrase after every browser restart and after "Lock". The saved Telegram login is encrypted with it.
 - Files of 64 MB or more ask where to save, then download straight to that file.
 - Log out wipes the Telegram session and the key from this browser.
