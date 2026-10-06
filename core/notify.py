"""Outbound notifications (webhook, Discord, Telegram).

Notifications are summaries by default.  Coordinates are never put on the wire
unless the operator sets ``notify.include_location`` - it is surprisingly easy
to leak sensitive data into a chat channel that has a much wider audience than
the console.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from . import config, utils


def _post_json(url: str, payload: dict, timeout: float = 6.0) -> bool:
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'seeker/2.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        utils.warn(f'notification failed: {exc}')
        return False


def _discord_embed(title: str, fields: Dict[str, Any], colour: int = 0x2ECC71) -> dict:
    return {
        'content': None,
        'embeds': [
            {
                'title': title,
                'color': colour,
                'fields': [
                    {'name': str(k), 'value': str(v)[:1000] or '—', 'inline': True}
                    for k, v in fields.items()
                ],
            }
        ],
    }


def _telegram_markdown_v2(text: str) -> str:
    escape = '_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + ch if ch in escape else ch for ch in text)


def send_telegram(token_spec: str, text: str) -> bool:
    try:
        token, chat_id = token_spec.split(':', 1)
    except ValueError:
        utils.warn('telegram token must look like token:chatId')
        return False
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    data = json.dumps(
        {'chat_id': chat_id, 'text': _telegram_markdown_v2(text), 'parse_mode': 'MarkdownV2'}
    ).encode('utf-8')
    req = urllib.request.Request(
        url, data=data, headers={'Content-Type': 'application/json'}
    )
    try:
        with urllib.request.urlopen(req, timeout=6):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        utils.warn(f'telegram notification failed: {exc}')
        return False


def notify_event(settings, event: Dict[str, Any], location_desc: str = ''):
    """Send one compact notification for an event (no-op if unconfigured)."""
    cfg = settings.notify
    if not cfg.enabled():
        return
    etype = event.get('type')
    payload = event.get('payload') or {}
    title = f"Seeker · {etype}"
    fields = {
        'campaign': event.get('campaign_id') or '—',
        'recipient': event.get('rid') or '—',
        'time': event.get('ts') or '—',
    }
    if etype == 'location':
        fields['location'] = location_desc if cfg.include_location else 'shared (redacted)'
        if payload.get('accuracy_m'):
            fields['accuracy'] = f"{payload['accuracy_m']} m"
    elif etype == 'report':
        fields['note'] = 'target reported the page (good outcome)'
        fields['reason'] = payload.get('reason') or 'not provided'
    elif etype == 'consent':
        fields['decision'] = payload.get('decision')
    elif etype == 'open':
        fields['note'] = 'tracking link opened'
    else:
        fields.update({k: str(v)[:80] for k, v in list(payload.items())[:6]})

    if cfg.webhook:
        if 'discord.com/api/webhooks' in cfg.webhook:
            _post_json(cfg.webhook, _discord_embed(title, fields))
        else:
            _post_json(cfg.webhook, {'type': etype, **fields})
    if cfg.telegram:
        lines = [f'*{title}*'] + [f'{k}: {v}' for k, v in fields.items()]
        send_telegram(cfg.telegram, '\n'.join(lines))
