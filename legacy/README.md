# legacy — Seeker v1

The original tool, preserved verbatim after the v2 rewrite:

```
seeker_v1.py          the original script (flat files + PHP)
utils_v1.py           print helper / image download
telegram_api_v1.py    Telegram sender
discord_webhook_v1.py Discord sender
php_v1/               error.php, info.php, result.php
js_v1/location.js     the geolocation + fingerprinting client
```

Run it (still needs `php`, `requests`, `psutil`, `packaging`):

```bash
cd ..                       # v1 resolves paths relative to the repository root
python3 legacy/seeker_v1.py
```

The v1 directories `template/`, `php/`, `js/` used to sit at the repository
root; `php/` and `js/` moved here, `template/` stayed at the root because the
page assets reference each other by relative path.

v1 is kept for reference and comparison only. It has known correctness bugs
that v2 fixes — see `README.md` → «ما الذي تغيّر؟» and `docs/MIGRATION.md`.
The v2 engine does not serve anything from `template/`.
