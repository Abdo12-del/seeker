"""Data-minimisation engine.

The point of this module: the platform should be able to answer the question
"did you really need to store that?" with a machine-readable policy instead of
a promise.  Location fixes are degraded *before* they are persisted, never
after, so a raw coordinate never touches the database when the policy says it
should not.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional

from .config import PrivacyPolicy

_GEO_BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz'


def geohash_encode(lat: float, lon: float, precision: int = 5) -> str:
    """Minimal, dependency-free geohash encoder."""
    precision = max(1, min(int(precision), 12))
    lat_min, lat_max = -90.0, 90.0
    lon_min, lon_max = -180.0, 180.0
    out = []
    bits = 0
    bit_count = 0
    is_even = True
    while len(out) < precision:
        if is_even:
            mid = (lon_min + lon_max) / 2
            if lon >= mid:
                bits = (bits << 1) + 1
                lon_min = mid
            else:
                bits = (bits << 1) + 0
                lon_max = mid
        else:
            mid = (lat_min + lat_max) / 2
            if lat >= mid:
                bits = (bits << 1) + 1
                lat_min = mid
            else:
                bits = (bits << 1) + 0
                lat_max = mid
        is_even = not is_even
        bit_count += 1
        if bit_count == 5:
            out.append(_GEO_BASE32[bits])
            bits = 0
            bit_count = 0
    return ''.join(out)


def geohash_center(geo: str):
    """Return the approximate centre of a geohash tile (for maps/KML)."""
    if not geo:
        return None, None
    lat_min, lat_max = -90.0, 90.0
    lon_min, lon_max = -180.0, 180.0
    is_even = True
    for char in geo.lower():
        idx = _GEO_BASE32.find(char)
        if idx < 0:
            return None, None
        for mask in (16, 8, 4, 2, 1):
            if is_even:
                mid = (lon_min + lon_max) / 2
                if idx & mask:
                    lon_min = mid
                else:
                    lon_max = mid
            else:
                mid = (lat_min + lat_max) / 2
                if idx & mask:
                    lat_min = mid
                else:
                    lat_max = mid
            is_even = not is_even
    return round((lat_min + lat_max) / 2, 4), round((lon_min + lon_max) / 2, 4)


def round_coord(value: float, precision: str) -> Optional[float]:
    if value is None:
        return None
    if precision == 'exact':
        return round(value, 6)
    if precision == 'approx':
        return round(value, 3)
    if precision == 'city':
        return round(value, 1)
    return None  # geohash / none handled elsewhere


def degrade_location(lat, lon, accuracy=None, policy: PrivacyPolicy = None) -> Dict[str, Any]:
    """Apply the precision policy to a coordinate pair.

    Returns a dict that is safe to persist: it never contains a raw fix unless
    the policy explicitly allows one.
    """
    policy = policy or PrivacyPolicy()
    result: Dict[str, Any] = {
        'shared': lat is not None and lon is not None,
        'precision': policy.precision,
    }
    if not result['shared']:
        return result

    lat_f, lon_f = float(lat), float(lon)
    if policy.precision in ('exact', 'approx', 'city'):
        result['lat'] = round_coord(lat_f, policy.precision)
        result['lon'] = round_coord(lon_f, policy.precision)
    elif policy.precision == 'geohash':
        result['geohash'] = geohash_encode(lat_f, lon_f, policy.geohash_precision)
    else:  # none
        result['lat'] = None
        result['lon'] = None

    if accuracy is not None and policy.precision in ('exact', 'approx'):
        result['accuracy_m'] = round(float(accuracy), 1)
    return result


def describe_location(record: Dict[str, Any]) -> str:
    """Human readable, policy-aware description of a stored location."""
    if not record or not record.get('shared'):
        return 'not shared'
    if record.get('geohash'):
        lat, lon = geohash_center(record['geohash'])
        return f"tile {record['geohash']} (~{lat}, {lon})"
    if record.get('lat') is not None:
        return f"{record['lat']}, {record['lon']} ({record.get('precision', '?')})"
    return 'shared (coordinates not stored)'


def pseudonymize_ip(ip: str, salt: str) -> str:
    if not ip:
        return ''
    return hashlib.sha256(f'{salt}|{ip}'.encode('utf-8')).hexdigest()[:16]


_SCREEN_RE = re.compile(r'^\d{2,5}$')


def sanitize_device(payload: Dict[str, Any], policy: PrivacyPolicy) -> Dict[str, Any]:
    """Keep the telemetry that has training value and drop the rest."""
    out: Dict[str, Any] = {}
    if not isinstance(payload, dict):
        return out
    if not policy.store_device_details:
        return out

    def pick(key, cast=str, maxlen=64):
        value = payload.get(key)
        if value is None:
            return None
        try:
            value = cast(value)
        except (TypeError, ValueError):
            return None
        if isinstance(value, str):
            value = value.strip()[:maxlen]
        return value or None

    out['os'] = pick('os')
    out['platform'] = pick('platform')
    out['browser'] = pick('browser')
    out['cores'] = pick('cores')
    out['ram_gb'] = pick('ram')
    out['gpu_vendor'] = pick('vendor')
    out['gpu_renderer'] = pick('render')
    width = pick('wd')
    height = pick('ht')
    if _SCREEN_RE.match(str(width or '')) and _SCREEN_RE.match(str(height or '')):
        out['screen'] = f'{width}x{height}'
    if policy.store_user_agent:
        out['user_agent'] = str(payload.get('ua') or '')[:300] or None
    return {k: v for k, v in out.items() if v is not None}


def retention_cutoff_iso(retention_days: int) -> Optional[str]:
    from datetime import datetime, timedelta, timezone

    if not retention_days:
        return None
    return (
        datetime.now(timezone.utc) - timedelta(days=int(retention_days))
    ).isoformat(timespec='milliseconds')
