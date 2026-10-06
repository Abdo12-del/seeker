# Migration from v1

The v1 tool is untouched in `legacy/` and still runs where PHP is available:

```bash
python3 legacy/seeker_v1.py -t 0     # needs: php, requests, psutil, packaging
```

Nothing in v2 reads v1's `logs/*.txt`, `db/results.csv` or `pid` file, so there
is no automatic data migration — and deliberately so: v1 rows cannot be
attributed to a session or linked to a signed authorisation, so importing them
would silently produce records that do not satisfy the v2 invariants. If you
need the old numbers, keep them as a CSV archive next to the new database.

## Command mapping

| v1 | v2 |
|---|---|
| `seeker.py -t 0` (interactive template) | `seeker.py campaign create --scenario nearyou …` then `serve` |
| `seeker.py -p 8080` | `seeker.py serve --port 8080` |
| `seeker.py -k file` (KML per hit) | `seeker.py export <id> -f kml` (whole campaign) |
| `seeker.py -tg token:chat` | `seeker.py serve --telegram token:chat` (summaries only) |
| `seeker.py -wh https://…` | `seeker.py serve --webhook https://…` |
| `seeker.py -u` | `git pull` (update check was a JSON fetch) |
| — | `seeker.py analyze <url\|file>` |
| — | `seeker.py ledger verify` |
| — | `seeker.py doctor` |

## Environment variables

v1 read `PORT`, `TEMPLATE`, `TELEGRAM`, `WEBHOOK`, `DEBUG_HTTP`. v2 keeps
`PORT`/`TELEGRAM`/`WEBHOOK` for compatibility and adds:

`SEEKER_HOST`, `SEEKER_PORT`, `SEEKER_TOKEN`, `SEEKER_BASE_URL`,
`SEEKER_LANG`, `SEEKER_ORG`, `SEEKER_CONTACT`, `SEEKER_WEBHOOK`,
`SEEKER_TELEGRAM`, `SEEKER_PRECISION`, `SEEKER_RETENTION_DAYS`,
`SEEKER_IP_RECON`, `SEEKER_DATA_DIR`, `SEEKER_TRUST_PROXY`, `SEEKER_QUIET`,
`SEEKER_DEBUG`.

`DEBUG_HTTP` is gone: v2 does not force an HTTPS redirect in the page at all.
Terminate TLS (or a tunnel) in front of it.

## Templates

`template/` (Google Drive, WhatsApp, Telegram, Zoom, reCAPTCHA …) is **not**
registered with the v2 engine. Those pages impersonate third-party brands;
serving them requires a licence/authorisation from the brand owner and a
signed record in the campaign. The v2 scenarios in `scenarios/` are generic and
brand-free. You can still port a page by adding a `manifest.json` and setting
`requires_brand_authorization` honestly.
