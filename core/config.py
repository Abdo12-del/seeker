"""Configuration objects and persistence for Seeker."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional

from . import utils

#: Coordinate precision policies.  Ordered from most to least identifying.
PRECISIONS = ('exact', 'approx', 'city', 'geohash', 'none')


@dataclass
class PrivacyPolicy:
    """How much identifying detail the platform is allowed to keep.

    Everything in here exists so an operator can *prove* data minimisation
    during an audit instead of claiming it.
    """

    #: exact  -> keep the raw fix (only for tightly scoped, authorised ops)
    #: approx -> round to ~110 m (3 decimals)
    #: city   -> round to ~11 km (1 decimal)
    #: geohash-> store a geohash tile instead of a point (default, ~5 km)
    #: none   -> never persist coordinates, only a boolean "shared location"
    precision: str = 'geohash'
    geohash_precision: int = 5
    #: Days an event is kept before automatic purge.  0 disables purging.
    retention_days: int = 30
    #: Store a salted hash of the IP instead of the address itself.
    pseudonymize_ip: bool = True
    #: Keep device telemetry (screen/GPU/cores).  Off = collect almost nothing.
    store_device_details: bool = True
    #: Keep raw user agents (they are quasi-identifiers).
    store_user_agent: bool = False
    #: Query a third party (ipwho.is) to enrich the public IP.  Sends the
    #: target's IP address to an external service, so it is off by default.
    ip_recon: bool = False

    def validate(self):
        if self.precision not in PRECISIONS:
            raise ValueError(f'precision must be one of {PRECISIONS}')
        if not 1 <= int(self.geohash_precision) <= 9:
            raise ValueError('geohash_precision must be between 1 and 9')
        if int(self.retention_days) < 0:
            raise ValueError('retention_days cannot be negative')
        return self


@dataclass
class NotifyConfig:
    """Outbound notifications.  All optional."""

    webhook: Optional[str] = None
    telegram: Optional[str] = None  # token:chatId
    #: Never let raw coordinates leave the box unless explicitly allowed.
    include_location: bool = False
    #: Only send a compact summary line, never the raw payload.
    summary_only: bool = True

    def enabled(self) -> bool:
        return bool(self.webhook or self.telegram)


@dataclass
class Settings:
    host: str = '0.0.0.0'
    port: int = 8080
    #: Bearer token protecting the API and the dashboard.
    token: Optional[str] = None
    #: Public base URL used when generating tracking links.
    base_url: Optional[str] = None
    lang: str = 'ar'  # 'ar' | 'en'
    #: Organisation running the simulation - shown on the consent notice.
    org_name: str = 'Security Awareness Team'
    contact: str = 'security@example.org'
    #: Refuse to serve any simulation page without a signed authorisation.
    require_authorization: bool = True
    privacy: PrivacyPolicy = field(default_factory=PrivacyPolicy)
    notify: NotifyConfig = field(default_factory=NotifyConfig)

    # ------------------------------------------------------------------
    def validate(self):
        self.privacy.validate()
        if self.lang not in ('ar', 'en'):
            raise ValueError("lang must be 'ar' or 'en'")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError('port out of range')
        return self

    @property
    def data_dir(self) -> str:
        return _data_dir

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop('token', None)
        return data

    def save(self, path: Optional[str] = None):
        path = path or os.path.join(_data_dir, 'settings.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
        return path

    @classmethod
    def load(cls, path: Optional[str] = None) -> 'Settings':
        path = path or os.path.join(_data_dir, 'settings.json')
        obj = cls()
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as handle:
                raw = json.load(handle)
            priv = raw.pop('privacy', None) or {}
            note = raw.pop('notify', None) or {}
            obj = cls(**{k: v for k, v in raw.items() if k in cls.__dataclass_fields__})
            obj.privacy = PrivacyPolicy(**priv)
            obj.notify = NotifyConfig(**note)
        obj.apply_env()
        return obj

    def apply_env(self):
        env_map = {
            'SEEKER_HOST': ('host', str),
            'SEEKER_PORT': ('port', int),
            'SEEKER_TOKEN': ('token', str),
            'SEEKER_BASE_URL': ('base_url', str),
            'SEEKER_LANG': ('lang', str),
            'SEEKER_ORG': ('org_name', str),
            'SEEKER_CONTACT': ('contact', str),
            'SEEKER_WEBHOOK': ('notify.webhook', str),
            'SEEKER_TELEGRAM': ('notify.telegram', str),
            'SEEKER_PRECISION': ('privacy.precision', str),
            'SEEKER_RETENTION_DAYS': ('privacy.retention_days', int),
            'SEEKER_IP_RECON': ('privacy.ip_recon', _as_bool),
        }
        for key, (target, caster) in env_map.items():
            if key not in os.environ:
                continue
            value = caster(os.environ[key])
            if target.startswith('privacy.'):
                setattr(self.privacy, target.split('.', 1)[1], value)
            elif target.startswith('notify.'):
                setattr(self.notify, target.split('.', 1)[1], value)
            else:
                setattr(self, target, value)
        # Legacy environment names kept for compatibility with the v1 tool.
        if os.getenv('TELEGRAM') and not self.notify.telegram:
            self.notify.telegram = os.environ['TELEGRAM']
        if os.getenv('WEBHOOK') and not self.notify.webhook:
            self.notify.webhook = os.environ['WEBHOOK']
        if os.getenv('PORT') and not os.getenv('SEEKER_PORT'):
            try:
                self.port = int(os.environ['PORT'])
            except ValueError:
                pass
        return self

    @property
    def effective_token(self) -> str:
        if not self.token:
            self.token = _load_or_create_token()
        return self.token

    def base_url_for(self, port: int) -> str:
        if self.base_url:
            return self.base_url.rstrip('/')
        return f'http://127.0.0.1:{port}'


def _as_bool(value) -> bool:
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_data_dir = os.environ.get('SEEKER_DATA_DIR') or os.path.join(_root, 'data')


def set_data_dir(path: str):
    global _data_dir
    _data_dir = os.path.abspath(path)
    os.makedirs(_data_dir, exist_ok=True)
    os.makedirs(os.path.join(_data_dir, 'static'), exist_ok=True)
    return _data_dir


def data_dir() -> str:
    os.makedirs(_data_dir, exist_ok=True)
    return _data_dir


def _token_path() -> str:
    return os.path.join(data_dir(), '.api_token')


def _load_or_create_token() -> str:
    path = _token_path()
    if os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as handle:
            value = handle.read().strip()
        if value:
            return value
    value = utils.secrets_hex(18)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def secret_key() -> str:
    """Stable HMAC key used to sign authorisations and tracking tokens."""
    path = os.path.join(data_dir(), '.signing_key')
    if os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as handle:
            value = handle.read().strip()
        if value:
            return value
    value = utils.secrets_hex(32)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value
