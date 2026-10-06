"""Scenario registry and page renderer.

A *scenario* is the page a simulated target lands on.  Scenarios shipped with
this project are generic lures - a delivery confirmation, a Wi-Fi finder, a
local-offers page - and none of them impersonate a real brand.  Brand
impersonation is a legal and ethical decision that belongs to whoever owns the
authorisation, so the loader also refuses to serve scenarios flagged
``requires_brand_authorization`` unless the campaign record carries a written,
signed authorisation for that brand.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from . import authz, config, i18n, utils

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS_DIR = os.path.join(ROOT, 'scenarios')
LAYOUT_FILE = os.path.join(SCENARIOS_DIR, '_layout.html')


class ScenarioError(Exception):
    pass


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as handle:
        return handle.read()


def list_scenarios() -> List[Dict[str, Any]]:
    out = []
    if not os.path.isdir(SCENARIOS_DIR):
        return out
    for entry in sorted(os.listdir(SCENARIOS_DIR)):
        manifest_path = os.path.join(SCENARIOS_DIR, entry, 'manifest.json')
        if os.path.isfile(manifest_path):
            try:
                data = json.loads(_read(manifest_path))
            except json.JSONDecodeError:
                continue
            data['id'] = data.get('id') or entry
            out.append(data)
    return out


def get_scenario(sid: str) -> Dict[str, Any]:
    for item in list_scenarios():
        if item.get('id') == sid:
            return item
    raise ScenarioError(f'unknown scenario: {sid}')


def _content(scenario: Dict[str, Any], lang: str) -> Dict[str, str]:
    content = scenario.get('content') or {}
    return content.get(lang) or content.get('en') or {}


def render_page(campaign: Dict[str, Any], recipient: Dict[str, Any], settings,
                lang: Optional[str] = None) -> str:
    """Render the landing page for one recipient."""
    scenario = get_scenario(campaign.get('scenario') or 'delivery')
    if scenario.get('requires_brand_authorization'):
        authz_data = campaign.get('authz') or {}
        brand = (authz_data.get('brand') or '').strip().lower()
        expected = str(scenario.get('brand') or '').lower()
        if not brand or brand != expected:
            raise ScenarioError(
                'this scenario impersonates a third-party brand and requires a signed'
                ' brand authorisation in the campaign record'
            )

    lang = lang or campaign.get('lang') or settings.lang
    content = _content(scenario, lang)
    strings = i18n.table(lang)
    privacy = campaign.get('privacy') or {}
    retention_days = int(privacy.get('retention_days', settings.privacy.retention_days))
    notice = authz.consent_notice(
        lang=lang,
        org=settings.org_name,
        contact=settings.contact,
        retention_days=retention_days,
        version=campaign.get('notice_version') or authz.NOTICE_VERSION,
    )
    precision_label = {
        'exact': 'exact point',
        'approx': '~110 m',
        'city': '~11 km',
        'geohash': f"tile only (~{privacy.get('geohash_precision', 5)} chars)",
        'none': 'coordinates are not stored',
    }.get(privacy.get('precision', 'geohash'), 'reduced')

    body_file = scenario.get('body_file')
    body = ''
    if body_file:
        body_path = os.path.join(SCENARIOS_DIR, str(scenario.get('id')), body_file)
        if os.path.isfile(body_path):
            body = _read(body_path)

    layout = _read(LAYOUT_FILE)
    values = {
        'LANG': lang,
        'DIR': 'rtl' if i18n.is_rtl(lang) else 'ltr',
        'TITLE': content.get('title') or scenario.get('name') or 'Seeker',
        'HEADLINE': content.get('headline') or '',
        'SUB': content.get('sub') or '',
        'CTA': content.get('cta') or strings.get('btn_continue', 'Continue'),
        'BODY': body,
        'ICON': scenario.get('icon') or '📍',
        'ACCENT': scenario.get('accent') or '#0f766e',
        'ORG': settings.org_name,
        'CONTACT': settings.contact,
        'NOTICE': notice.replace('\n', '<br>'),
        'NOTICE_TEXT': json.dumps(notice, ensure_ascii=False),
        'NOTICE_TITLE': strings.get('consent_title', 'Location request notice'),
        'BTN_ALLOW': strings.get('btn_allow', 'Share my approximate location'),
        'BTN_DENY': strings.get('btn_deny', 'Decline'),
        'BTN_REPORT': strings.get('btn_report', 'Report this page'),
        'BTN_BACK': strings.get('btn_back', 'Back to safety'),
        'REPORT_PROMPT': strings.get('report_prompt', 'Why are you reporting this page?'),
        'TOKEN': recipient.get('token', ''),
        'CAMPAIGN': campaign.get('id', ''),
        'SESSION': utils.secrets_hex(8),
        'PRECISION_LABEL': precision_label,
        'RETENTION_DAYS': str(retention_days),
        'STRINGS': json.dumps(strings, ensure_ascii=False),
        'SCENARIO': scenario.get('id', ''),
        'APP_BADGE': strings.get('app_badge', 'security awareness simulation'),
        'REPORT_PROMPT': strings.get('report_prompt', 'Why?'),
    }
    html = layout
    for key, value in values.items():
        html = html.replace('{{' + key + '}}', str(value))
    return html
