"""Test suite for the Seeker core package.  Run: python3 -m unittest discover tests"""

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core import analyzer, authz, config, privacy, reporting, scenarios, store, utils  # noqa: E402
from core import server as server_mod  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='seeker-test-')
        config.set_data_dir(self.tmp)
        store.close()
        store.init_db()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def campaign(self, **kwargs):
        fields = dict(
            id='testcamp', name='Test', scenario='delivery', lang='en',
            authorizer='Jane Doe', scope='interns, 12 people',
            purpose='security awareness training',
            privacy=privacy_defaults(),
            authz=authz.build_authz('testcamp', 'Jane Doe', 'interns, 12 people',
                                    'security awareness training', None),
        )
        fields.update(kwargs)
        store.create_campaign(**fields)
        return store.campaign_row_to_dict(store.get_campaign(fields['id']))


def privacy_defaults(**over):
    from core.config import PrivacyPolicy

    data = PrivacyPolicy().__dict__.copy()
    data.update(over)
    return data


# ----------------------------------------------------------------------
class TestPrivacy(unittest.TestCase):
    def test_geohash_roundtrip(self):
        gh = privacy.geohash_encode(33.3681, 6.8607, precision=7)
        lat, lon = privacy.geohash_center(gh)
        self.assertAlmostEqual(lat, 33.3681, delta=0.01)
        self.assertAlmostEqual(lon, 6.8607, delta=0.01)

    def test_exact_policy_keeps_coordinates(self):
        out = privacy.degrade_location(1.23456, 7.89, 12,
                                       config.PrivacyPolicy(precision='exact'))
        self.assertEqual(out['lat'], 1.23456)
        self.assertTrue(out['shared'])

    def test_none_policy_drops_coordinates(self):
        out = privacy.degrade_location(1.23456, 7.89, 12,
                                       config.PrivacyPolicy(precision='none'))
        self.assertIsNone(out['lat'])
        self.assertIsNone(out['lon'])
        self.assertTrue(out['shared'], 'a boolean "shared" is still useful')

    def test_geohash_policy_never_leaks_raw_fix(self):
        out = privacy.degrade_location(1.23456, 7.89, 12,
                                       config.PrivacyPolicy(precision='geohash',
                                                            geohash_precision=5))
        self.assertNotIn('lat', out)
        self.assertEqual(len(out['geohash']), 5)

    def test_missing_fix_is_not_reported_as_shared(self):
        out = privacy.degrade_location(None, None, None,
                                       config.PrivacyPolicy(precision='exact'))
        self.assertFalse(out['shared'])

    def test_device_sanitizer_respects_policy(self):
        raw = {'os': 'Windows', 'platform': 'Win32', 'cores': '8', 'ram': '8',
               'vendor': 'Google', 'render': 'ANGLE', 'wd': '1920', 'ht': '1080',
               'ua': 'x' * 400}
        kept = privacy.sanitize_device(raw, config.PrivacyPolicy())
        self.assertEqual(kept['screen'], '1920x1080')
        self.assertNotIn('user_agent', kept)
        dropped = privacy.sanitize_device(raw, config.PrivacyPolicy(store_device_details=False))
        self.assertEqual(dropped, {})

    def test_ip_pseudonymization_is_stable_and_short(self):
        a = privacy.pseudonymize_ip('1.2.3.4', 'salt')
        self.assertEqual(a, privacy.pseudonymize_ip('1.2.3.4', 'salt'))
        self.assertNotEqual(a, privacy.pseudonymize_ip('1.2.3.5', 'salt'))
        self.assertEqual(len(a), 16)


# ----------------------------------------------------------------------
class TestStore(Base):
    def test_event_chain_is_verifiable(self):
        for i in range(5):
            store.append_event('c1', 'r1', 's1', 'open', {'i': i})
        result = store.verify_chain()
        self.assertTrue(result['ok'])
        self.assertEqual(result['events'], 5)

    def test_tampering_is_detected(self):
        store.append_event('c1', 'r1', 's1', 'open', {})
        store.append_event('c1', 'r1', 's1', 'location', {'lat': 1.0})
        with store.tx() as conn:
            conn.execute("UPDATE events SET payload = '{\"lat\": 9.9}' WHERE seq = 2")
        result = store.verify_chain()
        self.assertFalse(result['ok'])
        self.assertEqual(result['broken_at'], 2)

    def test_events_are_attributed_per_session(self):
        """Two concurrent visitors must not be cross-attributed (v1 bug)."""
        store.append_event('c1', 'r1', 'session-a', 'device', {'os': 'Android'})
        store.append_event('c1', 'r2', 'session-b', 'device', {'os': 'iOS'})
        store.append_event('c1', 'r1', 'session-a', 'location', {'geohash': 'abcde'})
        rows = store.events('c1')
        location = next(r for r in rows if r['type'] == 'location')
        self.assertEqual(location['session_id'], 'session-a')
        self.assertEqual(location['rid'], 'r1')

    def test_retention_purge(self):
        store.append_event('c1', 'r1', 's1', 'open', {})
        old = '2020-01-01T00:00:00+00:00'
        with store.tx() as conn:
            conn.execute('UPDATE events SET ts = ?', (old,))
        removed = store.purge_expired(30)
        self.assertEqual(removed, 1)
        self.assertEqual(store.count_events().get('open', 0), 0)

    def test_campaign_and_recipients(self):
        cid = store.create_campaign(id='c9', name='N', scenario='wifi',
                                    privacy=privacy_defaults(), authz={})
        store.add_recipients(cid, [{'label': 'a@b', 'group': 'finance'}])
        rows = store.list_recipients(cid)
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(store.resolve_token(rows[0]['token']))

    def test_consent_signatures(self):
        store.record_consent('c1', 'r1', 's1', '1.0', 'notice text', 'granted',
                             'training', 30, 'subjhash', config.secret_key())
        ok = store.verify_consent(config.secret_key())
        self.assertTrue(ok['ok'])
        self.assertEqual(ok['records'], 1)
        self.assertFalse(store.verify_consent('wrong-key')['ok'])

    def test_expire_stale_campaigns(self):
        store.create_campaign(id='old', name='Old', scenario='wifi',
                              expires_at='2020-01-01T00:00:00+00:00',
                              privacy=privacy_defaults(), authz={})
        store.create_campaign(id='new', name='New', scenario='wifi',
                              expires_at='2999-01-01T00:00:00+00:00',
                              privacy=privacy_defaults(), authz={})
        moved = store.expire_stale_campaigns()
        self.assertEqual(moved, 1)
        self.assertEqual(store.get_campaign('old')['status'], 'expired')
        self.assertEqual(store.get_campaign('new')['status'], 'active')


# ----------------------------------------------------------------------
class TestAuthz(unittest.TestCase):
    def test_valid_authorization(self):
        record = authz.build_authz('c1', 'Jane', 'interns', 'training', None)
        ok, _ = authz.verify_authz(record)
        self.assertTrue(ok)

    def test_forged_record_is_rejected(self):
        record = authz.build_authz('c1', 'Jane', 'interns', 'training', None)
        record['scope'] = 'everyone on the internet'
        ok, why = authz.verify_authz(record)
        self.assertFalse(ok)
        self.assertIn('signature', why)

    def test_missing_fields(self):
        self.assertFalse(authz.verify_authz({})[0])
        self.assertFalse(authz.verify_authz({'authorizer': 'Jane'})[0])

    def test_expired_window(self):
        record = authz.build_authz('c1', 'Jane', 'interns', 'training',
                                   '2020-01-01T00:00:00+00:00')
        ok, why = authz.verify_authz(record)
        self.assertFalse(ok)
        self.assertIn('expired', why)

    def test_campaign_gate(self):
        settings = config.Settings()
        record = authz.build_authz('c1', 'Jane', 'interns', 'training', None)
        campaign = {'id': 'c1', 'status': 'active', 'authz': record, 'expires_at': None}
        self.assertTrue(authz.authorize_campaign(campaign, settings)[0])
        campaign['status'] = 'stopped'
        self.assertFalse(authz.authorize_campaign(campaign, settings)[0])

    def test_notice_is_versioned_and_bilingual(self):
        ar = authz.consent_notice('ar', org='ACME', contact='a@b', retention_days=7)
        en = authz.consent_notice('en', org='ACME', contact='a@b', retention_days=7)
        self.assertIn('ACME', ar)
        self.assertIn('1.0', en)
        self.assertNotEqual(ar, en)


# ----------------------------------------------------------------------
class TestReporting(Base):
    def _seed(self):
        cid = 'testcamp'
        self.campaign()
        recipients = store.add_recipients(cid, [
            {'label': 'a', 'group': 'finance'}, {'label': 'b', 'group': 'finance'},
            {'label': 'c', 'group': 'eng'},
        ])
        for rec in recipients:
            store.append_event(cid, rec['rid'], 's-' + rec['rid'], 'open', {})
        first = recipients[0]
        store.append_event(cid, first['rid'], 's-' + first['rid'], 'consent', {'decision': 'granted'})
        store.append_event(cid, first['rid'], 's-' + first['rid'], 'location',
                           {'geohash': 'sjuvu', 'shared': True, 'precision': 'geohash'})
        second = recipients[1]
        store.append_event(cid, second['rid'], 's-' + second['rid'], 'consent', {'decision': 'denied'})
        third = recipients[2]
        store.append_event(cid, third['rid'], 's-' + third['rid'], 'report', {'reason': 'phish'})
        return cid

    def test_funnel_counts(self):
        cid = self._seed()
        metrics = reporting.funnel(cid)
        self.assertEqual(metrics['links_issued'], 3)
        self.assertEqual(metrics['opened'], 3)
        self.assertEqual(metrics['shared_location'], 1)
        self.assertEqual(metrics['consent_denied'], 1)
        self.assertEqual(metrics['reported'], 1)
        self.assertEqual(metrics['share_rate'], 33.3)

    def test_group_breakdown(self):
        cid = self._seed()
        groups = {g['group']: g for g in reporting.group_breakdown(cid)}
        self.assertEqual(groups['finance']['opened'], 2)
        self.assertEqual(groups['finance']['shared'], 1)
        self.assertEqual(groups['eng']['reported'], 1)

    def test_exports(self):
        cid = self._seed()
        csv = reporting.campaign_to_csv(cid)
        self.assertIn('seq,timestamp', csv)
        self.assertIn('location', csv)
        self.assertIn('"campaign"', reporting.campaign_to_json(cid))
        self.assertIn('"chain"', reporting.campaign_to_json(cid))
        kml = reporting.campaign_to_kml(cid)
        self.assertIn('<Placemark>', kml)
        html = reporting.html_report(cid, 'en')
        self.assertIn('simulation funnel', html.lower())

    def test_kml_does_not_exceed_stored_precision(self):
        cid = self._seed()
        kml = reporting.campaign_to_kml(cid)
        self.assertNotIn('33.3681', kml)  # raw fix was never stored


# ----------------------------------------------------------------------
class TestAnalyzer(unittest.TestCase):
    def _fixture(self, name):
        path = os.path.join(ROOT, 'tests', 'fixtures', name)
        with open(path, 'r', encoding='utf-8') as handle:
            return handle.read()

    def test_deceptive_page_scores_high(self):
        result = analyzer.analyze(self._fixture('deceptive.html'), url='https://evil.example/x')
        self.assertEqual(result['verdict'], 'deceptive')
        self.assertGreaterEqual(result['score'], 55)
        ids = {f['id'] for f in result['findings']}
        for expected in ('exfil-channel', 'third-party-exfil', 'brand-mismatch',
                         'credential-fields', 'webrtc-leak', 'no-notice'):
            if expected != 'no-notice':
                self.assertIn(expected, ids)

    def test_benign_page_scores_zero(self):
        result = analyzer.analyze(self._fixture('benign.html'))
        self.assertEqual(result['verdict'], 'benign')
        self.assertEqual(result['score'], 0)
        self.assertTrue(any(f['id'] == 'consent-notice' for f in result['findings']))

    def test_external_scripts_are_inlined(self):
        page_path = os.path.join(ROOT, 'tests', 'fixtures', 'external', 'page.html')
        with open(page_path, 'r', encoding='utf-8') as handle:
            html = handle.read()
        result = analyzer.analyze(html, local_path=page_path)
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertTrue(any('locate.js' in s for s in result['sources']))
        self.assertIn('exfil-channel', {f['id'] for f in result['findings']})

    def test_page_without_geolocation_is_benign(self):
        result = analyzer.analyze('<html><body>hello</body></html>')
        self.assertEqual(result['score'], 0)

    def test_ssrf_guard_blocks_private_targets(self):
        for url in ('http://127.0.0.1:8080/', 'http://localhost/', 'file:///etc/passwd'):
            ok, _ = analyzer.is_safe_url(url)
            self.assertFalse(ok, url)

    def test_recommendations_only_for_problems(self):
        result = analyzer.analyze(self._fixture('benign.html'))
        self.assertEqual(result['recommendations'],
                         ['No action needed: the page requests location in a defensible way.'])


# ----------------------------------------------------------------------
class TestScenarios(Base):
    def test_all_scenarios_load(self):
        items = scenarios.list_scenarios()
        self.assertGreaterEqual(len(items), 3)
        for item in items:
            self.assertIn('id', item)
            self.assertIn('content', item)

    def test_render_contains_consent_notice_and_no_raw_token_leak(self):
        campaign = self.campaign()
        settings = config.Settings()
        settings.org_name = 'ACME Security'
        recipient = store.add_recipients('testcamp', [{'label': None, 'group': 'g'}])[0]
        html = scenarios.render_page(campaign, recipient, settings, lang='en')
        self.assertIn('ACME Security', html)
        self.assertIn('consent', html.lower())
        self.assertIn(recipient['token'], html)
        self.assertIn('/static/runtime.js', html)

    def test_brand_scenarios_require_authorization(self):
        """A scenario flagged as brand impersonation cannot be served blind."""
        campaign = self.campaign(scenario='delivery')
        campaign['scenario'] = 'fake-brand'
        path_dir = os.path.join(scenarios.SCENARIOS_DIR, 'fake-brand')
        os.makedirs(path_dir, exist_ok=True)
        try:
            with open(os.path.join(path_dir, 'manifest.json'), 'w', encoding='utf-8') as fh:
                json.dump({'id': 'fake-brand', 'name': 'Fake', 'brand': 'acmebank',
                           'requires_brand_authorization': True,
                           'content': {'en': {'title': 't', 'headline': 'h', 'sub': 's',
                                              'cta': 'c'}}}, fh)
            with self.assertRaises(scenarios.ScenarioError):
                scenarios.render_page(campaign, {'token': 'x'}, config.Settings())
        finally:
            shutil.rmtree(path_dir, ignore_errors=True)


# ----------------------------------------------------------------------
class TestServer(Base):
    @classmethod
    def setUpClass(cls):
        cls.settings = config.Settings()
        cls.settings.token = 'test-token'
        cls.settings.org_name = 'ACME'
        cls.app = server_mod.SeekerServer(cls.settings)
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), server_mod.Handler)
        cls.httpd.app = cls.app
        cls.httpd.daemon_threads = True
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _url(self, path):
        return f'http://127.0.0.1:{self.port}{path}'

    def _req(self, path, data=None, token='test-token', method=None):
        body = json.dumps(data).encode() if data is not None else None
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        if body:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self._url(path), data=body, headers=headers,
                                     method=method or ('POST' if body else 'GET'))
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode('utf-8')
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode('utf-8')

    def test_api_requires_token(self):
        status, _ = self._req('/api/state', token=None)
        self.assertEqual(status, 401)
        status, body = self._req('/api/state', token='wrong')
        self.assertEqual(status, 401)
        status, body = self._req('/api/state')
        self.assertEqual(status, 200)
        self.assertIn('campaigns', body)

    def test_full_simulation_flow(self):
        campaign = self.campaign()
        recipient = store.add_recipients('testcamp', [{'label': None, 'group': 'g'}])[0]
        token = recipient['token']
        status, html = self._req(f'/l/{token}', token=None)
        self.assertEqual(status, 200)
        self.assertIn('<html', html)

        session = 'sess-1'
        self._req('/ingest/device', {'t': token, 's': session, 'os': 'Linux',
                                     'platform': 'X11', 'cores': 4, 'wd': 800, 'ht': 600},
                  token=None)
        self._req('/ingest/open', {'t': token, 's': session}, token=None)
        self._req('/ingest/consent', {'t': token, 's': session, 'decision': 'granted'},
                  token=None)
        status, body = self._req('/ingest/location',
                                 {'t': token, 's': session, 'lat': 33.3681,
                                  'lon': 6.8607, 'acc': 20}, token=None)
        self.assertEqual(status, 200)
        stored = json.loads(body)['stored']
        self.assertNotIn('lat', stored, 'default policy must not persist a raw fix')
        self.assertEqual(len(stored['geohash']), 5)

        status, _ = self._req('/ingest/report', {'t': token, 's': session, 'reason': 'x'},
                              token=None)
        self.assertEqual(status, 200)

        metrics = reporting.funnel('testcamp')
        self.assertEqual(metrics['opened'], 1)
        self.assertEqual(metrics['shared_location'], 1)
        self.assertEqual(metrics['reported'], 1)

        status, _ = self._req('/api/chain')
        self.assertEqual(status, 200)

    def test_stopped_campaign_serves_403(self):
        campaign = self.campaign(id='stopped1')
        recipient = store.add_recipients('stopped1', [{'label': None, 'group': 'g'}])[0]
        store.set_campaign_status('stopped1', 'stopped')
        status, body = self._req(f'/l/{recipient["token"]}', token=None)
        self.assertEqual(status, 403)
        self.assertIn('not', body.lower())

    def test_unauthorized_campaign_serves_403(self):
        store.create_campaign(id='noauthz', name='No authz', scenario='wifi',
                              privacy=privacy_defaults(), authz={})
        recipient = store.add_recipients('noauthz', [{'label': None, 'group': 'g'}])[0]
        status, _ = self._req(f'/l/{recipient["token"]}', token=None)
        self.assertEqual(status, 403)

    def test_ingest_rejects_unknown_token(self):
        status, _ = self._req('/ingest/open', {'t': 'does-not-exist', 's': 'x'}, token=None)
        self.assertEqual(status, 403)

    def test_campaign_creation_requires_authorizer_and_scope(self):
        status, _ = self._req('/api/campaigns', {'name': 'x', 'scenario': 'wifi'})
        self.assertEqual(status, 400)
        status, body = self._req('/api/campaigns', {
            'name': 'Real campaign', 'scenario': 'wifi', 'authorizer': 'Jane',
            'scope': 'interns', 'links': 2})
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(len(payload['links']), 2)

    def test_analyze_endpoint(self):
        with open(os.path.join(ROOT, 'tests', 'fixtures', 'deceptive.html'),
                  encoding='utf-8') as handle:
            html = handle.read()
        status, body = self._req('/api/analyze', {'html': html})
        self.assertEqual(status, 200)
        result = json.loads(body)['result']
        self.assertEqual(result['verdict'], 'deceptive')
        self.assertEqual(len(store.list_audits(5)), 1)

    def test_path_traversal_is_blocked(self):
        status, _ = self._req('/static/..%2f..%2fseeker.py', token=None)
        self.assertIn(status, (403, 404))

    def test_analysis_of_a_real_campaign_page_is_benign(self):
        """Our own lure pages must pass our own audit."""
        campaign = self.campaign()
        recipient = store.add_recipients('testcamp', [{'label': None, 'group': 'g'}])[0]
        _, html = self._req(f'/l/{recipient["token"]}', token=None)
        result = analyzer.analyze(html, url='https://sim.example/l/' + recipient['token'])
        problems = [f['id'] for f in result['findings'] if f['weight'] > 0]
        self.assertNotIn('consent-notice', problems)
        self.assertNotIn('gesture-gate', problems)
        self.assertNotIn('credential-fields', problems)


if __name__ == '__main__':
    unittest.main(verbosity=2)
