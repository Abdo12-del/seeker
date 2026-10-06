# Writing a scenario (v2)

This file replaces the v1 "create a template" instructions. In v2 a page is a
**scenario**: a directory with a `manifest.json`, rendered through
`scenarios/_layout.html`.

```
scenarios/
  _layout.html          shared chrome: lure card, consent sheet, teach-back
  delivery/manifest.json
  wifi/manifest.json
  offers/manifest.json
  survey/manifest.json
```

`web/runtime.js` is injected into every page and drives the flow:

```
page render  → POST /ingest/device   (sanitized by the privacy policy)
             → POST /ingest/open
CTA click    → POST /ingest/consent_prompt
             → consent sheet is shown  ← the notice, before any browser prompt
  allow      → POST /ingest/consent {granted}
             → navigator.geolocation.getCurrentPosition(...)
             → POST /ingest/location   (degraded by the precision policy)
  deny       → POST /ingest/consent {denied} → teach-back
report       → POST /ingest/report  {reason} → teach-back
```

## manifest.json

```json
{
  "id": "delivery",
  "name": "Delivery confirmation",
  "icon": "📦",
  "accent": "#0f766e",
  "description": "What this scenario pretends to be, in one line.",
  "requires_brand_authorization": false,
  "body_file": "body.html",
  "content": {
    "ar": {"title": "…", "headline": "…", "sub": "…", "cta": "…"},
    "en": {"title": "…", "headline": "…", "sub": "…", "cta": "…"}
  }
}
```

| field | meaning |
|---|---|
| `id` | directory name, used by `--scenario` |
| `icon` / `accent` | emoji and brand colour for the card |
| `requires_brand_authorization` | `true` if the page imitates a real brand — the engine then **refuses to serve it** unless the campaign's authorisation names that brand |
| `body_file` | optional extra HTML injected above the CTA |
| `content.<lang>` | `title`, `headline`, `sub`, `cta` per language |

## Rules we hold ourselves to

* **No real trademarks.** Shipped scenarios are generic: a parcel, a Wi-Fi
  finder, a local offer, a labelled survey. If you need a brand page, that is a
  licensing decision for the brand owner and for whoever signed the
  authorisation, not for the scenario loader.
* **The consent notice is not optional.** It is rendered from
  `core/i18n.py` + `core/authz.py` and carries the operator name, the purpose,
  the retention period and a contact address. You can change the wording; you
  cannot remove it.
* **No credential fields.** The layout has no form inputs by design.
* **The teach-back always runs.** Every ending (shared, declined, reported)
  explains what just happened — that moment is the whole point of the exercise.

## Custom layout

`_layout.html` supports these tokens:

`{{LANG}} {{DIR}} {{TITLE}} {{HEADLINE}} {{SUB}} {{CTA}} {{BODY}} {{ICON}}
{{ACCENT}} {{ORG}} {{CONTACT}} {{NOTICE}} {{NOTICE_TEXT}} {{NOTICE_TITLE}}
{{BTN_ALLOW}} {{BTN_DENY}} {{BTN_REPORT}} {{BTN_BACK}} {{REPORT_PROMPT}}
{{TOKEN}} {{CAMPAIGN}} {{SESSION}} {{PRECISION_LABEL}} {{RETENTION_DAYS}}
{{STRINGS}} {{SCENARIO}} {{APP_BADGE}}`

Anything you add must keep the `#consentMask` sheet and the
`#cta` / `#allowBtn` / `#denyBtn` / `#reportBtn` ids that `runtime.js` binds to.
