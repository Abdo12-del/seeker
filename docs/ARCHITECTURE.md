# Architecture

```
seeker.py                 thin entry point → core.cli.main
core/
  config.py               Settings / PrivacyPolicy / NotifyConfig, env + JSON
  utils.py                terminal output, hashing, HMAC, validation, safe_join
  i18n.py                 ar/en string table (consent notice, console, reports)
  privacy.py              geohash + precision degradation + device sanitizer
  store.py                SQLite schema, hash-chained events, consent ledger
  authz.py                signed authorisation gate + versioned consent notice
  recon.py                optional, opt-in IP enrichment (off by default)
  notify.py               webhook / Discord / Telegram summaries
  reporting.py            funnel metrics, group breakdown, CSV/JSON/KML/HTML
  scenarios.py            scenario registry + render (manifest driven)
  analyzer.py             defensive page auditor (heuristics + evidence)
  server.py               stdlib HTTP server: pages, ingest, API, SSE
  cli.py                  argparse command surface
web/                      console.html, app.js, styles.css, runtime.js
scenarios/<id>/           manifest.json (+ optional body.html)
tests/                    unittest suite + fixtures
legacy/                   the v1 tool, preserved verbatim
```

## Data model

```
campaigns   id, name, scenario, lang, authorizer, scope, purpose,
            created_at, expires_at, status, privacy(json), authz(json),
            notice_version
recipients  rid, campaign_id, label, grp, token, created_at
events      seq, ts, campaign_id, rid, session_id, type, payload(json),
            prev_hash, row_hash          ← hash chain
consent_ledger ts, campaign_id, rid, session_id, notice_version, notice_hash,
            decision, purpose, retention_days, subject_hash, signature
audit_runs  id, ts, target, score, verdict, findings(json)
```

### Why a hash chain

Each row stores `row_hash = sha256(prev_hash | ts | campaign | rid | session |
type | payload)` and `prev_hash` of the previous row, starting from a 64-zero
genesis. `store.verify_chain()` walks the log: any edit, deletion or reordering
breaks the chain at the first tampered sequence. It does not make the data
unforgeable (the key is local) but it makes silent editing detectable — which
is what an auditor asks for.

### Why `session_id` exists

v1 wrote device telemetry to one file and coordinates to another, then polled
both. Two concurrent visitors overwrote each other, and the parser could pair
one person's device with another person's fix. In v2 every event carries a
`session_id` minted per page render plus the `rid` from the tracking token, so
attribution is explicit and testable (`test_events_are_attributed_per_session`).

## Request flow

```
GET /l/<token>
  → store.resolve_token(token)                 → 404 if unknown
  → authz.authorize_campaign(campaign, settings) → 403 if not authorised
  → scenarios.render_page(campaign, recipient, settings)
      · consent notice built from i18n + policy (versioned, hashed)
      · runtime.js injected with token/campaign/session
POST /ingest/<kind>
  → resolve token (403 if unknown)
  → authorise campaign (403 if stopped/expired/unauthorised)
  → policy applied (privacy.degrade_location / sanitize_device)
  → store.append_event(...)  → hash chain + SSE broadcast + notification
```

Everything else under `/api/*` requires `Authorization: Bearer <token>`;
`compare_digest` is used so token comparison is not timing-dependent.

## Defensive analyser

`core/analyzer.py` is a heuristic scanner, not a verdict machine. It reports
findings with the evidence snippet that triggered them so a human can
disagree. Weights:

| check | weight |
|---|---|
| credential / payment fields | 25 |
| geolocation not user-initiated | 20 |
| no informed notice | 20 |
| location exfiltrated off the page | 20 |
| third-party brand mismatch | 18 |
| geolocation on page load | 15 |
| coordinates sent to a different host | 15 |
| WebRTC local-address enumeration | 12 |
| fingerprinting / anti-inspection / obfuscation / no operator identity | 10 |
| pressure language / redirect-after / records refusals | 8 |

Score ≥ 55 → `deceptive`, ≥ 25 → `suspicious`, else `benign`. External
same-origin scripts are inlined before scanning, and URL targets are checked
against private/loopback ranges to avoid SSRF.

## Security notes

* No PHP, no third-party packages, no build step.
* Static serving is restricted to `web/` and `os.path.basename`-filtered.
* Ingest bodies are capped at 64 KB and every field is length-clamped
  (`utils.clamp_text`).
* The console token is generated on first run and stored `0600`.
* `SEEKER_TRUST_PROXY=1` is required before `X-Forwarded-For` is honoured.
