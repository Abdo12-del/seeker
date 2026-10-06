"""Authorisation gate.

This is the piece that makes the platform defensible: a simulation is only
served when a named human has recorded that they are allowed to run it, for
whom, until when, and why.  The record is HMAC-signed so it can be produced
later as evidence without the database being trusted.

It deliberately does not do anything clever.  It just refuses.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from . import config, utils


class AuthorizationError(Exception):
    """Raised when a campaign is not allowed to run."""


NOTICE_VERSION = '1.0'


def build_authz(campaign_id: str, authorizer: str, scope: str, purpose: str,
                expires_at: Optional[str], reviewers=None) -> Dict[str, Any]:
    payload = {
        'campaign_id': campaign_id,
        'authorizer': authorizer,
        'scope': scope,
        'purpose': purpose,
        'expires_at': expires_at,
        'reviewers': reviewers or [],
        'created_at': utils.now_iso(),
    }
    canonical = _canonical(payload)
    payload['signature'] = utils.hmac_sign(config.secret_key(), canonical)
    return payload


def _canonical(payload: Dict[str, Any]) -> str:
    keys = ('campaign_id', 'authorizer', 'scope', 'purpose', 'expires_at', 'created_at')
    return '|'.join(str(payload.get(k, '')) for k in keys) + '|' + ','.join(payload.get('reviewers') or [])


def verify_authz(authz: Dict[str, Any]) -> Tuple[bool, str]:
    if not isinstance(authz, dict) or not authz:
        return False, 'missing authorization record'
    if not authz.get('authorizer'):
        return False, 'no named authorizer'
    if not authz.get('scope'):
        return False, 'no scope defined'
    if not authz.get('purpose'):
        return False, 'no purpose defined'
    signature = authz.get('signature')
    if not utils.hmac_verify(config.secret_key(), _canonical(authz), signature):
        return False, 'authorization signature is invalid (record was edited or forged)'
    expires = authz.get('expires_at')
    if expires:
        dt = utils.parse_iso(expires)
        if dt is None:
            return False, 'unparseable expiry date'
        if dt.timestamp() < utils.parse_iso(utils.now_iso()).timestamp():
            return False, 'authorization window has expired'
    return True, 'ok'


def authorize_campaign(campaign: Dict[str, Any], settings) -> Tuple[bool, str]:
    """Gate applied before any lure page is served."""
    if not campaign:
        return False, 'unknown campaign'
    if campaign.get('status') == 'stopped':
        return False, 'campaign is stopped'
    if campaign.get('status') == 'expired':
        return False, 'campaign has expired'
    if campaign.get('expires_at'):
        dt = utils.parse_iso(campaign['expires_at'])
        if dt and dt.timestamp() < utils.parse_iso(utils.now_iso()).timestamp():
            return False, 'campaign has expired'
    if not getattr(settings, 'require_authorization', True):
        return True, 'authorization gate disabled by configuration'
    return verify_authz(campaign.get('authz') or {})


CONSENT_TEMPLATE = {
    'en': (
        '{intro}\n\n'
        'Who is asking: {org}\n'
        'Why: {why}\n'
        'What is collected: {what}\n'
        'How long it is kept: {retention}\n'
        'Your choices: {rights}\n'
        'Questions: {contact}\n'
        'Notice version {version}'
    ),
    'ar': (
        '{intro}\n\n'
        'من يطلب: {org}\n'
        'السبب: {why}\n'
        'ما الذي يُجمع: {what}\n'
        'مدة الاحتفاظ: {retention}\n'
        'خياراتك: {rights}\n'
        'للاستفسار: {contact}\n'
        'إصدار الإشعار {version}'
    ),
}


def consent_notice(lang: str = 'ar', org: str = '', contact: str = '',
                   retention_days: int = 30, version: str = NOTICE_VERSION) -> str:
    from . import i18n

    template = CONSENT_TEMPLATE.get(lang, CONSENT_TEMPLATE['en'])
    return template.format(
        intro=i18n.t('consent_intro', lang),
        org=org,
        why=i18n.t('consent_why_body', lang),
        what=i18n.t('consent_what_body', lang),
        retention=i18n.t('consent_retention_body', lang, days=retention_days),
        rights=i18n.t('consent_rights_body', lang),
        contact=contact,
        version=version,
    )
