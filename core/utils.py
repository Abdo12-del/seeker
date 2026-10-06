"""Small shared helpers: terminal output, hashing, time, validation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

C_RED = '\033[31m'
C_GREEN = '\033[32m'
C_CYAN = '\033[36m'
C_YELLOW = '\033[33m'
C_WHITE = '\033[0m'
C_DIM = '\033[2m'
C_BOLD = '\033[1m'

_ANSI = re.compile(r'\x1b\[\d+(?:;\d+)*m')


def echo(text='', **kwargs):
    """Print, stripping ANSI colours when stdout is not a TTY."""
    if not sys.stdout.isatty():
        text = _ANSI.sub('', str(text))
    print(text, flush=True, **kwargs)


def info(text):
    echo(f'{C_GREEN}[+]{C_CYAN} {text}{C_WHITE}')


def warn(text):
    echo(f'{C_YELLOW}[!]{C_CYAN} {text}{C_WHITE}')


def error(text):
    echo(f'{C_RED}[-]{C_CYAN} {text}{C_WHITE}')


def heading(text):
    echo(f'{C_BOLD}{C_CYAN}{text}{C_WHITE}')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def parse_iso(value: str):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def sha256(data) -> str:
    if isinstance(data, (dict, list)):
        data = json.dumps(data, sort_keys=True, separators=(',', ':'))
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hmac_sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()


def hmac_verify(secret: str, payload: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(secret, payload), str(signature or ''))


def random_token(nbytes: int = 16) -> str:
    return secrets_hex(nbytes)


def secrets_hex(nbytes: int = 16) -> str:
    import secrets

    return secrets.token_hex(nbytes)


def clamp_text(value, max_len: int = 512, default: str = ''):
    """Coerce arbitrary POST input into a short, safe string."""
    if value is None:
        return default
    if isinstance(value, (int, float, bool)):
        value = str(value)
    if not isinstance(value, str):
        return default
    value = value.replace('\x00', '').strip()
    if len(value) > max_len:
        value = value[:max_len]
    return value if value else default


def to_float(value, default=None):
    try:
        if value is None or value == '':
            return default
        return float(str(value).replace(' deg', '').replace(' m', '').replace(' m/s', '').strip())
    except (TypeError, ValueError):
        return default


def ip_is_public(ip: str) -> bool:
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


def safe_join(root: str, *parts: str) -> str:
    """Join paths and guarantee the result stays inside *root*."""
    root = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root, *parts))
    if target == root or target.startswith(root + os.sep):
        return target
    raise ValueError('path traversal attempt blocked')


def human_delta(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m {seconds % 60}s'
    if seconds < 86400:
        return f'{seconds // 3600}h {(seconds % 3600) // 60}m'
    return f'{seconds // 86400}d {(seconds % 86400) // 3600}h'


def pct(part: float, total: float) -> float:
    return round((part / total) * 100, 1) if total else 0.0


def epoch_ms() -> int:
    return int(time.time() * 1000)
