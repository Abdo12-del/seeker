"""Dependency-free HTTP server: lure pages, ingest API, console API, SSE.

Deliberately built on ``http.server`` so the platform has no install step and
no supply chain: a trainer can drop it on a laptop with Python and go.  The
surface is split in two:

  * ``/l/<token>`` and ``/ingest/*`` are public - they are what the simulated
    visitor touches, and they are gated by the campaign authorisation instead
    of by credentials.
  * ``/api/*`` and ``/console`` are private - they need the bearer token.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from typing import Any, Dict, List, Optional, Tuple

from . import (analyzer, authz, config, i18n, notify, privacy, reporting,
               scenarios, store, utils)

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'web')
MAX_BODY = 64 * 1024

# event listeners for the live console
_subscribers: List['_Queue'] = []
_sub_lock = threading.Lock()


class _Queue:
    def __init__(self):
        import queue

        self.q = queue.Queue(maxsize=200)

    def put(self, item):
        try:
            self.q.put_nowait(item)
        except Exception:
            pass


def subscribe() -> _Queue:
    sub = _Queue()
    with _sub_lock:
        _subscribers.append(sub)
    return sub


def unsubscribe(sub: _Queue):
    with _sub_lock:
        if sub in _subscribers:
            _subscribers.remove(sub)


def _broadcast(event: Dict[str, Any]):
    with _sub_lock:
        listeners = list(_subscribers)
    payload = json.dumps(event, ensure_ascii=False)
    for sub in listeners:
        sub.put(payload)


class Router:
    """Tiny regex router, enough for the handful of routes we serve."""

    def __init__(self):
        self.routes: List[Tuple[str, str, Any]] = []

    def add(self, method: str, pattern: str, handler):
        self.routes.append((method, '^' + pattern + '$', handler))

    def match(self, method: str, path: str):
        for meth, pattern, handler in self.routes:
            if meth != method:
                continue
            match = re.match(pattern, path)
            if match:
                return handler, match.groups()
        return None, None


class SeekerServer:
    """Holds the shared state the request handlers need."""

    def __init__(self, settings: 'config.Settings'):
        self.settings = settings
        self.started_at = time.time()
        self.router = Router()
        self._wire()

    # -- helpers ------------------------------------------------------
    def record(self, campaign_id, rid, session, etype, payload, notify_text=''):
        event = store.append_event(campaign_id, rid, session, etype, payload)
        event['payload'] = payload
        _broadcast({'kind': 'event', 'event': event})
        try:
            notify.notify_event(self.settings, event, location_desc=notify_text)
        except Exception as exc:  # notifications must never break collection
            utils.warn(f'notify error: {exc}')
        return event

    def client_ip(self, handler) -> str:
        if os.getenv('SEEKER_TRUST_PROXY', '').lower() in ('1', 'true', 'yes'):
            forwarded = handler.headers.get('X-Forwarded-For', '')
            if forwarded:
                return forwarded.split(',')[0].strip()
        return handler.client_address[0]

    # -- routes -------------------------------------------------------
    def _wire(self):
        r = self.router
        r.add('GET', r'/', self.page_console)                # landing -> console
        r.add('GET', r'/console', self.page_console)
        r.add('GET', r'/static/([A-Za-z0-9_.-]+)', self.page_static)
        r.add('GET', r'/l/([A-Za-z0-9_-]{4,64})', self.page_lure)
        r.add('POST', r'/ingest/([a-z_]{2,24})', self.api_ingest)
        r.add('GET', r'/api/state', self.api_state)
        r.add('GET', r'/api/events', self.api_events)
        r.add('GET', r'/api/stream', self.api_stream)
        r.add('POST', r'/api/campaigns', self.api_create_campaign)
        r.add('POST', r'/api/campaigns/([A-Za-z0-9_-]{2,64})/status', self.api_campaign_status)
        r.add('GET', r'/api/campaigns/([A-Za-z0-9_-]{2,64})/links', self.api_campaign_links)
        r.add('GET', r'/api/campaigns/([A-Za-z0-9_-]{2,64})/export', self.api_export)
        r.add('DELETE', r'/api/campaigns/([A-Za-z0-9_-]{2,64})', self.api_delete_campaign)
        r.add('POST', r'/api/analyze', self.api_analyze)
        r.add('GET', r'/api/chain', self.api_chain)

    # -- public pages -------------------------------------------------
    def page_console(self, handler, args=()):
        handler.serve_file(os.path.join(WEB_DIR, 'console.html'), 'text/html; charset=utf-8')

    def page_static(self, handler, args):
        name = os.path.basename(args[0])
        path = os.path.join(WEB_DIR, name)
        if not os.path.isfile(path):
            return handler.send_json(404, {'error': 'not found'})
        ctype = {
            '.js': 'text/javascript; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.html': 'text/html; charset=utf-8',
            '.svg': 'image/svg+xml',
        }.get(os.path.splitext(name)[1], 'application/octet-stream')
        handler.serve_file(path, ctype, cache=True)

    def page_lure(self, handler, args):
        token = args[0]
        recipient = store.resolve_token(token)
        if not recipient:
            return handler.send_html(404, '<h1>404</h1><p>Unknown tracking link.</p>')
        campaign = store.campaign_row_to_dict(store.get_campaign(recipient['campaign_id']))
        allowed, why = authz.authorize_campaign(campaign, self.settings)
        if not allowed:
            lang = campaign.get('lang') or self.settings.lang
            title = 'Simulation not available' if lang == 'en' else 'المحاكاة غير متاحة'
            body = {
                'en': 'This simulation is not currently authorised to run, so no location '
                      'request is being made. Reason: {why}',
                'ar': 'هذه المحاكاة غير مصرّح بتشغيلها حاليًا، لذلك لم يتم طلب الموقع. السبب: {why}',
            }[lang if lang in ('ar', 'en') else 'en'].format(why=why)
            return handler.send_html(403, f'<h1>{title}</h1><p>{body}</p>')
        try:
            html = scenarios.render_page(campaign, recipient, self.settings)
        except scenarios.ScenarioError as exc:
            return handler.send_html(500, f'<h1>500</h1><p>{exc}</p>')
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/html; charset=utf-8')
        handler.send_header('Content-Length', str(len(html.encode('utf-8'))))
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('Referrer-Policy', 'no-referrer')
        handler.send_header('X-Content-Type-Options', 'nosniff')
        handler.end_headers()
        handler.wfile.write(html.encode('utf-8'))

    # -- ingest -------------------------------------------------------
    def api_ingest(self, handler, args):
        kind = args[0]
        body = handler.read_body()
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = _parse_form(body)
        if not isinstance(data, dict):
            data = {}

        token = utils.clamp_text(data.get('t'), 128)
        recipient = store.resolve_token(token) if token else None
        if not recipient:
            # every event must be attributable to a campaign; unattributed
            # traffic is dropped rather than stored as noise.
            return handler.send_json(403, {'error': 'unknown tracking link'})
        campaign_id = recipient['campaign_id']
        campaign = store.campaign_row_to_dict(store.get_campaign(campaign_id)) if campaign_id else {}
        if recipient:
            allowed, why = authz.authorize_campaign(campaign, self.settings)
            if not allowed:
                return handler.send_json(403, {'error': 'campaign not authorised', 'reason': why})
        session = utils.clamp_text(data.get('s'), 64)
        rid = recipient['rid'] if recipient else None
        policy = campaign.get('privacy') or self.settings.privacy.__dict__
        settings_policy = self.settings.privacy

        if kind == 'device':
            payload = privacy.sanitize_device(data, settings_policy)
            self.record(campaign_id, rid, session, 'device', payload)
            return handler.send_json(200, {'ok': True})

        if kind == 'open':
            payload = {'ref': utils.clamp_text(data.get('ref'), 300)}
            self.record(campaign_id, rid, session, 'open', payload)
            return handler.send_json(200, {'ok': True})

        if kind == 'consent_prompt':
            self.record(campaign_id, rid, session, 'consent_prompt', {})
            return handler.send_json(200, {'ok': True})

        if kind == 'consent':
            decision = utils.clamp_text(data.get('decision'), 16, 'denied')
            if decision not in ('granted', 'denied'):
                decision = 'denied'
            notice = authz.consent_notice(
                lang=campaign.get('lang') or self.settings.lang,
                org=self.settings.org_name,
                contact=self.settings.contact,
                retention_days=int(policy.get('retention_days', settings_policy.retention_days)),
                version=campaign.get('notice_version') or authz.NOTICE_VERSION,
            )
            subject = privacy.pseudonymize_ip(self.client_ip(handler), config.secret_key())
            store.record_consent(
                campaign_id, rid, session, campaign.get('notice_version') or authz.NOTICE_VERSION,
                notice, decision, campaign.get('purpose') or 'security awareness training',
                int(policy.get('retention_days', settings_policy.retention_days)),
                subject, config.secret_key(),
            )
            self.record(campaign_id, rid, session, 'consent', {'decision': decision})
            return handler.send_json(200, {'ok': True, 'notice_version':
                                           campaign.get('notice_version') or authz.NOTICE_VERSION})

        if kind == 'location':
            lat = utils.to_float(data.get('lat'))
            lon = utils.to_float(data.get('lon'))
            acc = utils.to_float(data.get('acc'))
            record = privacy.degrade_location(lat, lon, acc, settings_policy)
            record['precision'] = policy.get('precision', settings_policy.precision)
            if settings_policy.ip_recon:
                ip = self.client_ip(handler)
                geo = _recon(ip)
                if geo:
                    record['network'] = {'country': geo.get('country'), 'city': geo.get('city')}
            self.record(campaign_id, rid, session, 'location', record,
                        notify_text=privacy.describe_location(record))
            return handler.send_json(200, {'ok': True, 'stored': record})

        if kind == 'error':
            payload = {'error': utils.clamp_text(data.get('error'), 200)}
            self.record(campaign_id, rid, session, 'error', payload)
            return handler.send_json(200, {'ok': True})

        if kind == 'report':
            payload = {'reason': utils.clamp_text(data.get('reason'), 300)}
            self.record(campaign_id, rid, session, 'report', payload)
            return handler.send_json(200, {'ok': True, 'thanks': True})

        if kind == 'reveal':
            self.record(campaign_id, rid, session, 'reveal',
                        {'shared': bool(data.get('shared'))})
            return handler.send_json(200, {'ok': True})

        return handler.send_json(404, {'error': 'unknown ingest endpoint'})

    # -- private API --------------------------------------------------
    def api_state(self, handler, args=()):
        campaigns = store.list_campaigns()
        for campaign in campaigns:
            campaign['funnel'] = reporting.funnel(campaign['id'])
            allowed, why = authz.authorize_campaign(campaign, self.settings)
            campaign['authorized'] = allowed
            campaign['authorization_note'] = why
            campaign['links'] = len(store.list_recipients(campaign['id']))
        return handler.send_json(200, {
            'ok': True,
            'version': _version(),
            'uptime': int(time.time() - self.started_at),
            'lang': self.settings.lang,
            'org': self.settings.org_name,
            'precision': self.settings.privacy.precision,
            'retention_days': self.settings.privacy.retention_days,
            'require_authorization': self.settings.require_authorization,
            'campaigns': campaigns,
            'totals': reporting.funnel(),
            'groups': reporting.group_breakdown(),
            'scenarios': scenarios.list_scenarios(),
            'recent': store.events(limit=40),
            'audits': store.list_audits(10),
        })

    def api_events(self, handler, args=()):
        since = int(handler.query.get('since', ['0'])[0] or 0)
        campaign_id = handler.query.get('campaign', [None])[0]
        return handler.send_json(200, {
            'ok': True,
            'events': store.events(campaign_id=campaign_id, since_seq=since, limit=200),
            'chain': store.verify_chain(),
        })

    def api_chain(self, handler, args=()):
        return handler.send_json(200, {
            'ok': True,
            'events': store.verify_chain(),
            'consent': store.verify_consent(config.secret_key()),
        })

    def api_stream(self, handler, args=()):
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        handler.send_header('Cache-Control', 'no-cache')
        handler.send_header('Connection', 'keep-alive')
        handler.send_header('X-Accel-Buffering', 'no')
        handler.end_headers()
        sub = subscribe()
        try:
            handler.wfile.write(b': connected\n\n')
            handler.wfile.flush()
            while True:
                try:
                    payload = sub.q.get(timeout=20)
                except Exception:
                    handler.wfile.write(b': ping\n\n')
                    handler.wfile.flush()
                    continue
                data = ('data: ' + payload + '\n\n').encode('utf-8')
                handler.wfile.write(data)
                handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            unsubscribe(sub)

    def api_create_campaign(self, handler, args=()):
        body = handler.read_body()
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return handler.send_json(400, {'error': 'invalid JSON'})
        name = utils.clamp_text(data.get('name'), 120, 'Untitled campaign')
        scenario_id = utils.clamp_text(data.get('scenario'), 60, 'delivery')
        authorizer = utils.clamp_text(data.get('authorizer'), 120)
        scope = utils.clamp_text(data.get('scope'), 300)
        purpose = utils.clamp_text(data.get('purpose'), 300,
                                   'security awareness training')
        days = int(data.get('duration_days') or 7)
        if not authorizer or not scope:
            return handler.send_json(400, {
                'error': 'authorizer and scope are required - see docs/ETHICS.md'})
        expires = _iso_in_days(days)
        cid = utils.secrets_hex(6)
        record = authz.build_authz(cid, authorizer, scope, purpose, expires)
        store.create_campaign(
            id=cid, name=name, scenario=scenario_id,
            lang=data.get('lang') or self.settings.lang, authorizer=authorizer,
            scope=scope, purpose=purpose, expires_at=expires,
            privacy=self.settings.privacy.__dict__.copy(), authz=record,
        )
        entries = [{'label': None, 'group': data.get('group') or 'default'}]
        generated = store.add_recipients(
            cid, entries * max(1, int(data.get('links') or 1)))
        return handler.send_json(201, {
            'ok': True, 'id': cid, 'expires_at': expires,
            'links': [self.link_for(r['token']) for r in generated],
        })

    def api_campaign_status(self, handler, args):
        cid = args[0]
        body = handler.read_body()
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {}
        status = utils.clamp_text(data.get('status'), 20, 'stopped')
        if status not in ('active', 'stopped', 'expired'):
            return handler.send_json(400, {'error': 'bad status'})
        store.set_campaign_status(cid, status)
        return handler.send_json(200, {'ok': True, 'status': status})

    def api_campaign_links(self, handler, args):
        cid = args[0]
        rows = store.list_recipients(cid)
        return handler.send_json(200, {
            'ok': True,
            'links': [self.link_for(r['token']) for r in rows],
            'recipients': rows,
        })

    def api_delete_campaign(self, handler, args):
        cid = args[0]
        store.purge_campaign(cid)
        return handler.send_json(200, {'ok': True, 'deleted': cid})

    def api_export(self, handler, args):
        cid = args[0]
        fmt = (handler.query.get('format', ['json'])[0] or 'json').lower()
        if fmt == 'csv':
            payload, ctype, ext = reporting.campaign_to_csv(cid), 'text/csv; charset=utf-8', 'csv'
        elif fmt == 'kml':
            payload, ctype, ext = reporting.campaign_to_kml(cid), 'application/vnd.google-earth.kml+xml', 'kml'
        elif fmt == 'html':
            payload = reporting.html_report(cid, handler.query.get('lang', [self.settings.lang])[0])
            ctype, ext = 'text/html; charset=utf-8', 'html'
        else:
            payload, ctype, ext = reporting.campaign_to_json(cid), 'application/json', 'json'
        handler.send_response(200)
        handler.send_header('Content-Type', ctype)
        handler.send_header('Content-Disposition', f'attachment; filename="seeker-{cid}.{ext}"')
        handler.end_headers()
        handler.wfile.write(payload.encode('utf-8'))

    def api_analyze(self, handler, args=()):
        body = handler.read_body()
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return handler.send_json(400, {'error': 'invalid JSON'})
        url = utils.clamp_text(data.get('url'), 2048)
        markup = data.get('html') or ''
        run_id = utils.secrets_hex(6)
        try:
            if url:
                result = analyzer.analyze_url(url)
            elif markup:
                result = analyzer.analyze(str(markup)[:analyzer.MAX_FETCH_BYTES])
            else:
                return handler.send_json(400, {'error': 'provide url or html'})
        except analyzer.FetchError as exc:
            return handler.send_json(400, {'error': f'fetch failed: {exc}'})
        store.save_audit(run_id, url or 'pasted-html', result['score'],
                         result['verdict'], result['findings'])
        result['id'] = run_id
        return handler.send_json(200, {'ok': True, 'result': result})

    def link_for(self, token: str) -> str:
        """Absolute when a base URL is configured, otherwise host-relative.

        Host-relative links keep working whatever proxy or tunnel ends up in
        front of the server, and the console expands them with its own origin.
        """
        base = self.settings.base_url
        if base:
            return f'{base.rstrip("/")}/l/{token}'
        return f'/l/{token}'


def _version() -> str:
    from . import __version__

    return __version__


def _recon(ip: str):
    from . import recon

    return recon.lookup(ip)


def _iso_in_days(days: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat(timespec='seconds')


def _parse_form(body: bytes) -> Dict[str, str]:
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        return {}
    parsed = urllib.parse.parse_qs(text)
    return {k: v[0] for k, v in parsed.items() if v}


class Handler(BaseHTTPRequestHandler):
    server_version = 'Seeker/2.0'
    protocol_version = 'HTTP/1.1'

    # -- plumbing -----------------------------------------------------
    @property
    def app(self) -> SeekerServer:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        if os.getenv('SEEKER_QUIET', '') in ('1', 'true'):
            return
        utils.echo(f'{utils.C_DIM}[{self.log_date_time_string()}] {fmt % args}{utils.C_WHITE}')

    def read_body(self) -> bytes:
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return b''
        if length <= 0:
            return b''
        if length > MAX_BODY:
            return b''
        return self.rfile.read(length)

    def send_json(self, status: int, payload: dict):
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, status: int, html: str):
        raw = html.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def serve_file(self, path: str, ctype: str, cache: bool = False):
        if not os.path.isfile(path):
            return self.send_html(404, '<h1>404</h1>')
        with open(path, 'rb') as handle:
            raw = handle.read()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'public, max-age=60' if cache else 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    # -- dispatch -----------------------------------------------------
    def do_GET(self):
        self._dispatch('GET')

    def do_POST(self):
        self._dispatch('POST')

    def do_DELETE(self):
        self._dispatch('DELETE')

    def do_HEAD(self):
        self.send_json(200, {'ok': True})

    def _dispatch(self, method: str):
        parsed = urllib.parse.urlparse(self.path)
        self.query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path.rstrip('/') or '/'
        handler, args = self.app.router.match(method, path)
        if handler is None:
            handler, args = self.app.router.match(method, path + '/')
        if handler is None:
            return self.send_json(404, {'error': 'not found', 'path': path})

        if path.startswith('/api') and path != '/api/stream':
            if not self._authorized():
                return self.send_json(401, {'error': 'unauthorized'})
        elif path == '/api/stream':
            if not self._authorized():
                return self.send_json(401, {'error': 'unauthorized'})
        try:
            handler(self, args or ())
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # pragma: no cover - defensive
            import traceback

            utils.error(f'{exc}')
            if os.getenv('SEEKER_DEBUG'):
                traceback.print_exc()
            try:
                self.send_json(500, {'error': str(exc)})
            except Exception:
                pass

    def _authorized(self) -> bool:
        expected = self.app.settings.effective_token
        header = self.headers.get('Authorization', '')
        if header.startswith('Bearer '):
            return _safe_eq(header[7:].strip(), expected)
        token = (self.query.get('token') or [''])[0]
        if token:
            return _safe_eq(token, expected)
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            if part.strip().startswith('seeker_token='):
                return _safe_eq(part.strip().split('=', 1)[1], expected)
        return False


def _safe_eq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(str(a), str(b))


class Server(ThreadingHTTPServer):  # already threading via ThreadingMixIn
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler_cls, app: SeekerServer):
        self.app = app
        super().__init__(addr, handler_cls)


def serve(settings: 'config.Settings', port: Optional[int] = None,
          host: Optional[str] = None, open_console: bool = False) -> Server:
    store.init_db()
    port = port or settings.port
    host = host or settings.host
    app = SeekerServer(settings)
    httpd = Server((host, port), Handler, app)
    return httpd
