# Private prototype viewer

A static page for the Soarwave team. Everything behind the sign in is encrypted.
Without an account the files in this folder are unreadable.

## How it works

- Every image and the list of pages are encrypted with one random AES-256-GCM key.
  Each file has its own random IV and is stored as a `.bin` file in `data/`.
- `accounts.json` holds, for each account, a username, a random salt, the iteration
  count, an IV and the content key wrapped with a key derived from that account's
  password (PBKDF2-SHA256, 600000 iterations). It holds no password and no password hash.
- The browser derives the key with the Web Crypto API. The unwrapped key stays in memory
  and in `sessionStorage`, which is cleared on sign out and when the tab closes.
- The page loads nothing from other sites. A Content Security Policy enforces that.

## Rebuild

The build script and the account file live outside this folder and are never published.

```
python3 build.py                      # render every page, encrypt, write this folder
python3 build.py --skip-render        # accounts changed only
python3 build.py --add-account NAME   # add one account with a random password
```

Each build makes a new content key, so everyone signs in again after a rebuild,
and a removed account cannot read the new files.

## Limits

- This is static hosting. There is no server side rate limit. The protection is the
  password strength and the PBKDF2 cost, so use the long random passwords the build makes.
- The repository and its file sizes are public. Only the content is protected.
- Anyone who has an account can save what they see.
