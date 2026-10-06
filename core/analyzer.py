"""Defensive analyser: does this page harvest location deceptively?

This is the other half of the project.  Anyone can run a lure; far fewer
people can answer "would our staff notice?".  The analyser reads a page (or
fetches a URL) and scores it against the patterns that separate a legitimate
location feature from a covert harvesting page:

  * is the geolocation call gated behind an informed, specific notice?
  * is the fix exfiltrated, and to whom?
  * is the page pretending to be a brand it does not own?
  * is it fingerprinting or grabbing network details it does not need?

It is a heuristic scanner, not a verdict machine: findings come with the
evidence that triggered them so a human can disagree.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

MAX_FETCH_BYTES = 1_500_000
FETCH_TIMEOUT = 8.0

BRANDS = (
    'google', 'gdrive', 'drive.google', 'whatsapp', 'telegram', 'zoom', 'microsoft',
    'outlook', 'office', 'apple', 'icloud', 'facebook', 'instagram', 'paypal', 'amazon',
    'netflix', 'dhl', 'fedex', 'ups', 'aramex', 'bank', 'paypal',
)

URGENCY = (
    'urgent', 'immediately', 'action required', 'verify now', 'limited time',
    'your account will be', 'suspended', 'confirm your identity', 'final notice',
    'عاجل', 'فورًا', 'حالا', 'تحقق الآن', 'سيتم إيقاف', 'أكد هويتك', 'إنذار أخير',
)

CREDENTIAL_HINTS = ('type="password"', 'type=password', 'autocomplete="current-password"',
                    'cvv', 'card number', 'رقم البطاقة', 'كلمة المرور')

FINGERPRINT_HINTS = (
    'WEBGL_debug_renderer_info', 'UNMASKED_RENDERER_WEBGL', 'hardwareConcurrency',
    'deviceMemory', 'toDataURL', 'canvas', 'RTCPeerConnection', 'createDataChannel',
    'getStats', 'navigator.plugins', 'AudioContext',
)


class FetchError(Exception):
    pass


def is_safe_url(url: str) -> Tuple[bool, str]:
    """Block obvious SSRF targets before following a user-supplied URL."""
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return False, 'unparseable URL'
    if parts.scheme not in ('http', 'https'):
        return False, 'only http/https URLs are supported'
    host = parts.hostname
    if not host:
        return False, 'missing host'
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, 'host does not resolve'
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return False, f'host resolves to a private address ({addr})'
    return True, 'ok'


def fetch(url: str, timeout: float = FETCH_TIMEOUT) -> str:
    ok, why = is_safe_url(url)
    if not ok:
        raise FetchError(why)
    req = urllib.request.Request(url, headers={'User-Agent': 'seeker-audit/2.0'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_FETCH_BYTES)
            charset = resp.headers.get_content_charset() or 'utf-8'
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        raise FetchError(str(exc)) from exc
    return raw.decode(charset, 'replace')


def _snippet(text: str, match: re.Match, width: int = 160) -> str:
    start = max(0, match.start() - 30)
    end = min(len(text), match.end() + 60)
    snippet = text[start:end].replace('\n', ' ').strip()
    return ('…' if start else '') + snippet[:width] + ('…' if end < len(text) else '')


def _has(text: str, *needles: str) -> bool:
    low = text.lower()
    return any(n.lower() in low for n in needles)


def collect_scripts(html: str, url: Optional[str] = None,
                    local_path: Optional[str] = None,
                    max_files: int = 5, max_bytes: int = 200_000):
    """Inline same-origin external scripts so scanner patterns can see them.

    A page that looks harmless can do all the work in ``/js/locate.js``; only
    reading the HTML would miss it entirely.
    """
    import os as _os

    sources: List[str] = []
    parts: List[str] = []
    for match in re.finditer(r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', html, re.I):
        src = match.group(1).strip()
        if src.startswith('data:') or src.startswith('//'):
            src = 'https:' + src if src.startswith('//') else src
        if len(sources) >= max_files:
            break
        try:
            if url:
                target = urllib.parse.urljoin(url, src)
                ok, why = is_safe_url(target)
                if not ok:
                    sources.append(f'{src} (skipped: {why})')
                    continue
                parts.append(fetch(target)[:max_bytes])
                sources.append(target)
            elif local_path:
                base = _os.path.dirname(_os.path.abspath(local_path))
                target = _os.path.realpath(_os.path.join(base, src))
                if target != base and not target.startswith(base + _os.sep):
                    sources.append(f'{src} (skipped: outside base directory)')
                    continue
                if not _os.path.isfile(target):
                    sources.append(f'{src} (not found locally)')
                    continue
                with open(target, 'r', encoding='utf-8', errors='replace') as handle:
                    parts.append(handle.read(max_bytes))
                sources.append(target)
            else:
                continue
        except (FetchError, OSError):
            sources.append(f'{src} (unreachable)')
    return '\n'.join(parts), sources


def analyze(html: str, url: Optional[str] = None,
            local_path: Optional[str] = None) -> Dict[str, Any]:
    """Score a page.  Returns verdict, score, findings and recommendations."""
    findings: List[Dict[str, Any]] = []

    def add(fid, title, severity, weight, detail, evidence=''):
        findings.append({
            'id': fid, 'title': title, 'severity': severity, 'weight': weight,
            'detail': detail, 'evidence': evidence,
        })

    external_blob, sources = collect_scripts(html, url=url, local_path=local_path)
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)
    script_blob = '\n'.join(scripts) + '\n' + external_blob
    inline_all = html + '\n' + external_blob
    host = urllib.parse.urlparse(url or '').hostname or ''

    # --- 1. does the page touch geolocation at all? -------------------
    geo_matches = list(re.finditer(
        r'navigator\.geolocation\s*|getCurrentPosition\s*\(|watchPosition\s*\(', inline_all))
    if not geo_matches:
        add('no-geolocation', 'No geolocation API usage found', 'info', 0,
            'The page never asks for the browser location API.')
        return _result(0, 'benign', findings, url, html)

    add('geolocation-used', 'Page calls the Geolocation API', 'info', 0,
        f'{len(geo_matches)} reference(s) to navigator.geolocation.',
        _snippet(inline_all, geo_matches[0]))

    # --- 2. is the request gated behind a user gesture + notice? ------
    gesture = bool(
        re.search(r'addEventListener\(\s*[\'"]click[\'"]', script_blob)
        or re.search(r'onclick\s*=', inline_all, re.I)
        or re.search(r'onclick["\']?\s*:', script_blob)
    )
    add('gesture-gate', 'Location request is user-initiated' if gesture
        else 'Location request is NOT user-initiated',
        'info' if gesture else 'high', 0 if gesture else 20,
        'The call sits behind a click handler.' if gesture else
        'Geolocation is invoked without a click handler - the visitor is asked '
        'before they have done anything, which is the classic consent-bypass pattern.',
        '' if gesture else _snippet(inline_all, geo_matches[0]))

    onload = re.search(r'<body[^>]*onload\s*=|window\.onload|DOMContentLoaded', inline_all, re.I)
    if onload:
        add('auto-trigger', 'Location flow can trigger on page load', 'high', 15,
            'A load handler can run the flow before the visitor reads anything.',
            _snippet(inline_all, onload))

    notice_words = ('consent', 'privacy', 'permission notice', 'we will use your location',
                    'موافقة', 'خصوصية', 'إشعار', 'سنستخدم موقعك')
    has_notice = _has(inline_all, *notice_words)
    add('consent-notice', 'Informed notice present' if has_notice else 'No informed notice found',
        'info' if has_notice else 'high', 0 if has_notice else 20,
        'The page explains what is collected.' if has_notice else
        'No consent/privacy wording was found anywhere in the page. A browser '
        'permission prompt is not informed consent.')

    identifiable = re.search(r'(contact|privacy policy|terms|about us|تواصل|سياسة الخصوصية)',
                             inline_all, re.I)
    if not identifiable:
        add('unattributable', 'Page has no operator identity', 'medium', 10,
            'No contact, privacy policy or "about" reference - the visitor cannot '
            'tell who is asking them for location.')

    # --- 3. exfiltration ----------------------------------------------
    exfil_patterns = (
        r'\$\s*\.\s*(?:ajax|post)\s*\(', r'fetch\s*\(', r'XMLHttpRequest\s*\(',
        r'navigator\.sendBeacon', r'new Image\(\)\.src',
    )
    exfil = [m for p in exfil_patterns for m in re.finditer(p, script_blob, re.I)]
    location_keys = r'(lat|lon|lng|long|latitude|longitude|accuracy|altitude|coords|position)'
    if exfil:
        targets = re.findall(r"""(?:url\s*:\s*|fetch\s*\(\s*|\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*)['"]([^'"]{2,240})['"]""",
                             script_blob, re.I)
        external = [t for t in targets if t.startswith(('http://', 'https://'))]
        foreign = [t for t in external if host and urllib.parse.urlparse(t).hostname
                   and urllib.parse.urlparse(t).hostname != host]
        key_hit = re.search(location_keys, script_blob, re.I)
        add('exfil-channel', 'Location data is transmitted off the page', 'high', 20,
            f'{len(exfil)} network call(s) found'
            + (' carrying coordinate-named fields.' if key_hit else '.'),
            _snippet(script_blob, exfil[0]))
        if foreign:
            add('third-party-exfil', 'Coordinates go to a different host', 'high', 15,
                'The receiving host differs from the page host, so the visitor is '
                'sharing location with a party they never identified.',
                ', '.join(sorted(set(foreign))[:3]))
    else:
        add('no-exfil', 'No outbound channel detected', 'info', 0,
            'The page appears to use the location locally.')

    # --- 4. handling of a "no" ----------------------------------------
    if re.search(r'showError|error_handler|errorHandler|PERMISSION_DENIED', script_blob):
        add('tracks-denial', 'The page records refusals too', 'medium', 8,
            'Denials are reported back to the server, i.e. the operator counts who '
            'said no. Legitimate location features rarely need this.')

    # --- 5. fingerprinting --------------------------------------------
    fp_hits = [h for h in FINGERPRINT_HINTS if _has(script_blob, h)]
    if fp_hits:
        add('fingerprinting', 'Device fingerprinting present', 'medium', 10,
            'Beyond location the page collects: ' + ', '.join(fp_hits[:6]) + '.',
            ', '.join(fp_hits[:4]))

    if _has(script_blob, 'RTCPeerConnection', 'createDataChannel'):
        add('webrtc-leak', 'WebRTC / local address enumeration', 'high', 12,
            'RTCPeerConnection can expose local and public IP addresses even behind '
            'a VPN, with no permission prompt at all.')

    # --- 6. brand mismatch --------------------------------------------
    title_match = re.search(r'<title[^>]*>(.*?)</title>', inline_all, re.S | re.I)
    title_text = title_match.group(1).strip() if title_match else ''
    brand_hits = sorted({b for b in BRANDS if b in (title_text + ' ' + inline_all[:4000]).lower()})
    if brand_hits and host:
        mismatch = not any(b.replace(' ', '') in host.replace('-', '').lower() for b in brand_hits)
        if mismatch:
            add('brand-mismatch', 'Uses third-party brand names', 'high', 18,
                f'References {", ".join(brand_hits[:5])} but is served from {host}. '
                'Brand impersonation is the core of a lure.',
                title_text[:120])

    # --- 7. pressure & credentials ------------------------------------
    urgency_hits = [u for u in URGENCY if u in inline_all.lower()]
    if urgency_hits:
        add('urgency', 'Pressure / urgency language', 'medium', 8,
            'Urgency reduces deliberation before a permission prompt.',
            ', '.join(urgency_hits[:4]))

    cred_hits = [c for c in CREDENTIAL_HINTS if c in inline_all.lower()]
    if cred_hits:
        add('credential-fields', 'Credential or payment fields present', 'high', 25,
            'The page asks for secrets as well as location.', ', '.join(cred_hits[:4]))

    # --- 8. evasion / cloaking ----------------------------------------
    if _has(script_blob, 'window.location = "https:"', 'window.location.replace',
            'document.location.href ='):
        add('redirect-after', 'Redirects the visitor elsewhere', 'medium', 8,
            'A bounce-back to a legitimate site is used to make the detour forgettable.')

    if _has(script_blob, 'oncontextmenu', 'preventDefault', 'devtools', 'HeadlessChrome',
            'bot', 'crawler'):
        add('anti-analysis', 'Anti-inspection or bot filtering', 'medium', 10,
            'The page tries to detect or hinder inspection, which legitimate '
            'location features have no reason to do.')

    if re.search(r'eval\s*\(|atob\s*\(|Function\s*\(\s*[\'"]return', script_blob):
        add('obfuscation', 'Obfuscated JavaScript', 'medium', 10,
            'Encoding or dynamic evaluation hides what the page actually does.')

    if sources:
        add('external-scripts', 'External scripts were loaded for inspection', 'info', 0,
            'These same-origin scripts were pulled in and scanned as part of the page: '
            + '; '.join(sources[:5]))

    score = sum(f['weight'] for f in findings)
    score = min(100, score)
    if score >= 55:
        verdict = 'deceptive'
    elif score >= 25:
        verdict = 'suspicious'
    else:
        verdict = 'benign'
    result = _result(score, verdict, findings, url, html)
    result['sources'] = sources
    return result


RECOMMENDATIONS = {
    'no-geolocation': ['Nothing to do - the page does not request location.'],
    'gesture-gate': ['Move the geolocation call behind an explicit button the visitor chooses to press.'],
    'auto-trigger': ['Never request location on page load; wait for a deliberate action.'],
    'consent-notice': [
        'Show who is asking, why, what is stored and for how long, before the browser prompt.',
        'Publish a privacy notice and link it from the page.',
    ],
    'unattributable': ['Add operator identity: organisation name and a contact address.'],
    'exfil-channel': ['Send the minimum necessary: a coarse area, not a raw fix.'],
    'third-party-exfil': ['Stop shipping coordinates to a host the visitor never identified.'],
    'tracks-denial': ['Do not record refusals; there is no product reason to.'],
    'fingerprinting': ['Drop device fingerprinting you cannot justify in your privacy notice.'],
    'webrtc-leak': ['Remove WebRTC enumeration - it exposes local addresses without consent.'],
    'brand-mismatch': ['Remove third-party branding you are not licensed to use.'],
    'urgency': ['Remove countdowns and threat language around permission prompts.'],
    'credential-fields': ['Never combine a permission prompt with credential capture.'],
    'redirect-after': ['Do not silently bounce visitors to a real site afterwards.'],
    'anti-analysis': ['Remove bot filtering and inspection blocking.'],
    'obfuscation': ['Ship readable JavaScript; obfuscation is itself a trust signal.'],
}


def _result(score: int, verdict: str, findings: List[Dict[str, Any]],
            url: Optional[str], html: str) -> Dict[str, Any]:
    seen, recs = set(), []
    for finding in findings:
        if not finding.get('weight'):
            continue  # the check passed - there is nothing to fix
        for rec in RECOMMENDATIONS.get(finding['id'], []):
            if rec not in seen:
                seen.add(rec)
                recs.append(rec)
    if not recs:
        recs = ['No action needed: the page requests location in a defensible way.']
    return {
        'score': score,
        'verdict': verdict,
        'findings': findings,
        'recommendations': recs,
        'url': url,
        'size': len(html),
        'checked_at': __import__('datetime').datetime.now(
            __import__('datetime').timezone.utc).isoformat(timespec='seconds'),
    }


def analyze_url(url: str) -> Dict[str, Any]:
    return analyze(fetch(url), url=url)
