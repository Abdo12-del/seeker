"""Optional, opt-in enrichment of a public IP address.

Off by default: sending a person's IP to a third party is itself processing of
personal data, so it only happens when the operator explicitly enables it and
even then the result is cached and failures are silent.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from . import config, utils

CACHE_TTL = 3600
_cache: Dict[str, tuple] = {}


def enabled(settings=None) -> bool:
    settings = settings or config.Settings.load()
    return bool(settings.privacy.ip_recon)


def lookup(ip: str, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    """Return coarse network metadata for a public IP, or None."""
    if not ip or not utils.ip_is_public(ip):
        return None
    hit = _cache.get(ip)
    if hit and (utils.epoch_ms() / 1000 - hit[0]) < CACHE_TTL:
        return hit[1]
    url = f'https://ipwho.is/{ip}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'seeker/2.0 (+awareness)'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode('utf-8', 'replace'))
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None
    if not raw.get('success', True):
        return None
    data = {
        'country': raw.get('country'),
        'region': raw.get('region'),
        'city': raw.get('city'),
        'org': raw.get('connection', {}).get('org') if isinstance(raw.get('connection'), dict) else None,
        'asn': raw.get('connection', {}).get('asn') if isinstance(raw.get('connection'), dict) else None,
        'is_proxy': bool(raw.get('security', {}).get('proxy')) if isinstance(raw.get('security'), dict) else None,
    }
    data = {k: v for k, v in data.items() if v not in (None, '')}
    _cache[ip] = (utils.epoch_ms() / 1000, data)
    return data or None
