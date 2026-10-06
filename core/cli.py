"""Command line interface.

    seeker serve                       run the console + simulation server
    seeker campaign create ...         create an authorised campaign
    seeker links add <id> --count N    issue tracking links
    seeker report <id>                 funnel metrics
    seeker export <id> --format html   csv | json | kml | html
    seeker analyze <url|file>          audit a page for deceptive location use
    seeker ledger verify               check the audit chain + consent signatures
    seeker doctor                      environment sanity check
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional

from . import (analyzer, authz, config, i18n, reporting, scenarios, store,
               utils)

BANNER = r"""
             _
  ___  ___| | _____ _ __
 / __|/ _ \ |/ / _ \ '__|
 \__ \  __/   <  __/ |
 |___/\___|_|\_\___|_|      awareness edition
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='seeker',
        description='Authorized security-awareness simulations and deceptive-location audits.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Every simulation command requires a named authorizer and a scope. '
               'See docs/ETHICS.md.',
    )
    parser.add_argument('-v', '--version', action='store_true')
    parser.add_argument('--data-dir', help='where campaigns and events are stored')
    sub = parser.add_subparsers(dest='command')

    # serve -----------------------------------------------------------
    serve = sub.add_parser('serve', help='run the console and simulation server')
    serve.add_argument('-p', '--port', type=int)
    serve.add_argument('-H', '--host')
    serve.add_argument('--token', help='console/API bearer token')
    serve.add_argument('--base-url', help='public base URL used in tracking links')
    serve.add_argument('--lang', choices=('ar', 'en'))
    serve.add_argument('--org')
    serve.add_argument('--contact')
    serve.add_argument('--webhook')
    serve.add_argument('--telegram')
    serve.add_argument('--precision', choices=config.PRECISIONS)
    serve.add_argument('--retention-days', type=int)
    serve.add_argument('--allow-unauthorized', action='store_true',
                       help='disable the authorisation gate (not recommended)')

    # campaigns -------------------------------------------------------
    camp = sub.add_parser('campaign', help='manage campaigns')
    camp_sub = camp.add_subparsers(dest='action')
    create = camp_sub.add_parser('create', help='create an authorised campaign')
    create.add_argument('--name', required=True)
    create.add_argument('--scenario', default='delivery')
    create.add_argument('--authorizer', required=True,
                        help='named human who approved this simulation')
    create.add_argument('--scope', required=True,
                        help='who may be targeted, e.g. "finance team, 40 people"')
    create.add_argument('--purpose', default='security awareness training')
    create.add_argument('--duration-days', type=int, default=7)
    create.add_argument('--links', type=int, default=1)
    create.add_argument('--group', default='default')
    create.add_argument('--lang', choices=('ar', 'en'))
    create.add_argument('--precision', choices=config.PRECISIONS)
    create.add_argument('--retention-days', type=int)
    camp_sub.add_parser('list', help='list campaigns')
    stop = camp_sub.add_parser('stop', help='stop a campaign')
    stop.add_argument('id')
    purge = camp_sub.add_parser('purge', help='delete a campaign and all its data')
    purge.add_argument('id')
    purge.add_argument('--yes', action='store_true')

    # links -----------------------------------------------------------
    links = sub.add_parser('links', help='tracking links')
    links_sub = links.add_subparsers(dest='action')
    add = links_sub.add_parser('add')
    add.add_argument('campaign_id')
    add.add_argument('--count', type=int, default=1)
    add.add_argument('--group', default='default')
    add.add_argument('--labels', nargs='*', help='optional recipient labels/groups')
    add.add_argument('--base-url')
    links_sub.add_parser('list').add_argument('campaign_id')

    # report / export -------------------------------------------------
    report = sub.add_parser('report', help='funnel metrics for a campaign')
    report.add_argument('campaign_id', nargs='?')
    export = sub.add_parser('export', help='export a campaign')
    export.add_argument('campaign_id')
    export.add_argument('-f', '--format', choices=('csv', 'json', 'kml', 'html'),
                        default='json')
    export.add_argument('-o', '--out')
    export.add_argument('--lang', choices=('ar', 'en'))

    # analyze ---------------------------------------------------------
    ana = sub.add_parser('analyze', help='audit a page for deceptive location use')
    ana.add_argument('target', help='URL or path to an HTML file')
    ana.add_argument('--json', action='store_true')

    # misc ------------------------------------------------------------
    ledger = sub.add_parser('ledger', help='integrity of the audit log')
    ledger.add_argument('action', choices=('verify', 'show'))
    ledger.add_argument('campaign_id', nargs='?')
    sub.add_parser('doctor', help='environment checks')
    sub.add_parser('scenarios', help='list available scenarios')
    retention = sub.add_parser('purge-expired', help='apply the retention policy now')
    retention.add_argument('--days', type=int)
    return parser


# ----------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        from . import __version__

        utils.echo(__version__)
        return 0

    if getattr(args, 'data_dir', None):
        config.set_data_dir(args.data_dir)
    config.data_dir()
    store.init_db()

    command = args.command
    if command == 'serve':
        return cmd_serve(args)
    if command == 'campaign':
        return cmd_campaign(args)
    if command == 'links':
        return cmd_links(args)
    if command == 'report':
        return cmd_report(args)
    if command == 'export':
        return cmd_export(args)
    if command == 'analyze':
        return cmd_analyze(args)
    if command == 'ledger':
        return cmd_ledger(args)
    if command == 'doctor':
        return cmd_doctor(args)
    if command == 'scenarios':
        return cmd_scenarios(args)
    if command == 'purge-expired':
        return cmd_purge_expired(args)
    build_parser().print_help()
    return 1


# ----------------------------------------------------------------------
def _settings_from_args(args) -> 'config.Settings':
    settings = config.Settings.load()
    for src, dst in (('host', 'host'), ('base_url', 'base_url'), ('lang', 'lang'),
                     ('org', 'org_name'), ('contact', 'contact'),
                     ('webhook', 'notify.webhook'), ('telegram', 'notify.telegram'),
                     ('precision', 'privacy.precision'),
                     ('retention_days', 'privacy.retention_days')):
        value = getattr(args, src, None)
        if value in (None, ''):
            continue
        if dst.startswith('notify.'):
            setattr(settings.notify, dst.split('.', 1)[1], value)
        elif dst.startswith('privacy.'):
            setattr(settings.privacy, dst.split('.', 1)[1], value)
        else:
            setattr(settings, dst, value)
    if getattr(args, 'port', None):
        settings.port = int(args.port)
    if getattr(args, 'token', None):
        settings.token = args.token
    if getattr(args, 'allow_unauthorized', False):
        settings.require_authorization = False
    settings.validate()
    return settings


def cmd_serve(args) -> int:
    from . import server as server_mod

    settings = _settings_from_args(args)
    settings.save()
    token = settings.effective_token
    httpd = server_mod.serve(settings)
    expired = store.expire_stale_campaigns()
    if expired:
        utils.warn(f'{expired} campaign(s) moved to expired')

    utils.echo(f'{utils.C_CYAN}{BANNER}{utils.C_WHITE}')
    utils.info(f'version   : {_version()}')
    utils.info(f'console   : http://{settings.host}:{settings.port}/console')
    utils.info(f'token     : {utils.C_YELLOW}{token}{utils.C_WHITE}')
    utils.info(f'precision : {settings.privacy.precision} · retention '
               f'{settings.privacy.retention_days}d')
    utils.info(f'data dir  : {config.data_dir()}')
    utils.info(f'auth gate : '
               f'{"ON" if settings.require_authorization else utils.C_RED + "OFF" + utils.C_WHITE}')
    utils.echo()
    utils.echo(f'{utils.C_DIM}ctrl+c to stop{utils.C_WHITE}')
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        utils.warn('shutting down')
    finally:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
    return 0


def _version() -> str:
    from . import __version__

    return __version__


def cmd_campaign(args) -> int:
    settings = config.Settings.load()
    if args.action == 'create':
        expires = _iso_in_days(args.duration_days)
        cid = utils.secrets_hex(6)
        privacy = settings.privacy.__dict__.copy()
        if args.precision:
            privacy['precision'] = args.precision
        if args.retention_days is not None:
            privacy['retention_days'] = args.retention_days
        record = authz.build_authz(cid, args.authorizer, args.scope, args.purpose, expires)
        store.create_campaign(
            id=cid, name=args.name, scenario=args.scenario,
            lang=args.lang or settings.lang, authorizer=args.authorizer, scope=args.scope,
            purpose=args.purpose, expires_at=expires, privacy=privacy, authz=record,
        )
        created = store.add_recipients(
            cid, [{'label': None, 'group': args.group} for _ in range(max(1, args.links))]
        )
        utils.info(f'campaign {cid} created (authorised by {args.authorizer})')
        utils.info(f'expires  {expires}')
        base = settings.base_url_for(settings.port)
        for item in created:
            utils.echo(f'  {base}/l/{item["token"]}')
        if args.links == 1:
            utils.echo(f'{utils.C_DIM}  one anonymous link: share widely, it is not '
                       f'personally attributable{utils.C_WHITE}')
        return 0

    if args.action == 'list':
        campaigns = store.list_campaigns()
        if not campaigns:
            utils.warn('no campaigns yet — see `seeker campaign create --help`')
            return 0
        store.expire_stale_campaigns()
        for campaign in campaigns:
            allowed, why = authz.authorize_campaign(campaign, settings)
            metrics = reporting.funnel(campaign['id'])
            flag = f'{utils.C_GREEN}authorised{utils.C_WHITE}' if allowed else \
                f'{utils.C_RED}{why}{utils.C_WHITE}'
            utils.echo(
                f'\n{utils.C_CYAN}{campaign["id"]}{utils.C_WHITE}  {campaign["name"]}'
                f'  [{campaign["status"]}] {flag}\n'
                f'  scenario   {campaign["scenario"]}   authorizer {campaign["authorizer"]}\n'
                f'  scope      {campaign["scope"]}\n'
                f'  links {metrics["links_issued"]} · opened {metrics["opened"]}'
                f' · shared {metrics["shared_location"]} · declined {metrics["consent_denied"]}'
                f' · reported {metrics["reported"]}'
            )
        return 0

    if args.action == 'stop':
        store.set_campaign_status(args.id, 'stopped')
        utils.info(f'{args.id} stopped — pages now return 403')
        return 0

    if args.action == 'purge':
        if not args.yes:
            utils.warn(f'this deletes campaign {args.id} and every event it collected')
            answer = input('type the campaign id to confirm: ').strip()
            if answer != args.id:
                utils.error('aborted')
                return 1
        store.purge_campaign(args.id)
        utils.info(f'{args.id} deleted')
        return 0
    return 1


def cmd_links(args) -> int:
    settings = config.Settings.load()
    base = args.base_url if getattr(args, 'base_url', None) else settings.base_url_for(settings.port)
    campaign = store.get_campaign(args.campaign_id)
    if campaign is None:
        utils.error('unknown campaign')
        return 1
    if args.action == 'add':
        entries = []
        if args.labels:
            for label in args.labels:
                entries.append({'label': label, 'group': args.group})
        else:
            entries = [{'label': None, 'group': args.group} for _ in range(max(1, args.count))]
        created = store.add_recipients(args.campaign_id, entries)
        for item in created:
            utils.echo(f'  {base}/l/{item["token"]}   '
                       f'{utils.C_DIM}{item.get("label") or args.group}{utils.C_WHITE}')
        utils.info(f'{len(created)} link(s) issued')
        return 0
    if args.action == 'list':
        for item in store.list_recipients(args.campaign_id):
            utils.echo(f'  {item["rid"]}  {base}/l/{item["token"]}  '
                       f'{utils.C_DIM}{item.get("label") or item.get("grp")}{utils.C_WHITE}')
        return 0
    return 1


def cmd_report(args) -> int:
    metrics = reporting.funnel(args.campaign_id)
    utils.heading('simulation funnel')
    width = max(len(k) for k in metrics)
    for key, value in metrics.items():
        utils.echo(f'  {key.ljust(width)} : {value}')
    groups = reporting.group_breakdown(args.campaign_id)
    if groups:
        utils.heading('\nby group')
        for group in groups:
            utils.echo(f'  {group["group"]:<16} opened {group["opened"]:<4} '
                       f'shared {group["shared"]:<4} reported {group["reported"]:<4} '
                       f'share {group["share_rate"]}%')
    return 0


def cmd_export(args) -> int:
    campaign_id = args.campaign_id
    if args.format == 'csv':
        payload = reporting.campaign_to_csv(campaign_id)
    elif args.format == 'kml':
        payload = reporting.campaign_to_kml(campaign_id)
    elif args.format == 'html':
        payload = reporting.html_report(campaign_id, args.lang or config.Settings.load().lang)
    else:
        payload = reporting.campaign_to_json(campaign_id)
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as handle:
            handle.write(payload)
        utils.info(f'written to {args.out}')
    else:
        utils.echo(payload)
    return 0


def cmd_analyze(args) -> int:
    target = args.target
    try:
        if target.startswith(('http://', 'https://')):
            result = analyzer.analyze_url(target)
        elif os.path.isfile(target):
            with open(target, 'r', encoding='utf-8', errors='replace') as handle:
                result = analyzer.analyze(handle.read(analyzer.MAX_FETCH_BYTES),
                                              local_path=target)
        else:
            utils.error('target must be a URL or an existing file')
            return 1
    except analyzer.FetchError as exc:
        utils.error(f'could not fetch: {exc}')
        return 1

    if args.json:
        utils.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    colour = {'benign': utils.C_GREEN, 'suspicious': utils.C_YELLOW,
              'deceptive': utils.C_RED}[result['verdict']]
    utils.heading(f"\n{result['url'] or 'pasted HTML'} ({result['size']} bytes)")
    utils.echo(f"  verdict : {colour}{result['verdict'].upper()}{utils.C_WHITE}"
               f"   score {result['score']}/100")
    if result['findings']:
        utils.heading('\n  findings')
    for finding in result['findings']:
        mark = {'info': '·', 'low': '-', 'medium': '!', 'high': '!'}[finding['severity']]
        utils.echo(f"  [{mark}] {finding['title']}  ({finding['severity']}, "
                   f"+{finding['weight']})")
        utils.echo(f"      {finding['detail']}")
        if finding['evidence']:
            utils.echo(f"{utils.C_DIM}      evidence: {finding['evidence'][:150]}"
                       f"{utils.C_WHITE}")
    utils.heading('\n  recommendations')
    for rec in result['recommendations']:
        utils.echo(f'  - {rec}')
    store.save_audit(utils.secrets_hex(6), target, result['score'], result['verdict'],
                     result['findings'])
    utils.echo()
    return 0


def cmd_ledger(args) -> int:
    chain = store.verify_chain()
    consent = store.verify_consent(config.secret_key())
    if args.action == 'verify':
        ok = chain['ok'] and consent['ok']
        status = 'intact' if chain['ok'] else f"BROKEN at seq {chain['broken_at']}"
        utils.info(f"events  : {chain['events']} checked, {status}")
        utils.info(f"consent : {consent['records']} records, "
                   f"{'all signatures valid' if consent['ok'] else 'invalid: ' + str(consent['invalid'])}")
        return 0 if ok else 2
    rows = store.consent_rows(args.campaign_id)
    for row in rows:
        utils.echo(f"  {row['ts']}  {row['campaign_id']}  {row['decision']:<8} "
                   f"notice v{row['notice_version']}  {row['notice_hash'][:12]}…")
    utils.info(f'{len(rows)} consent record(s)')
    return 0


def cmd_doctor(args) -> int:
    import platform
    import sqlite3

    checks = [
        ('python', platform.python_version(),
         tuple(map(int, platform.python_version().split('.'))) >= (3, 8)),
        ('sqlite', sqlite3.sqlite_version, True),
        ('data dir', config.data_dir(), os.path.isdir(config.data_dir())),
        ('database', store.db_path(), os.path.isfile(store.db_path())),
        ('scenarios', str(len(scenarios.list_scenarios())),
         bool(scenarios.list_scenarios())),
        ('layout', scenarios.LAYOUT_FILE, os.path.isfile(scenarios.LAYOUT_FILE)),
        ('console', os.path.join(scenarios.ROOT, 'web', 'console.html'),
         os.path.isfile(os.path.join(scenarios.ROOT, 'web', 'console.html'))),
    ]
    failed = 0
    for name, value, ok in checks:
        flag = f'{utils.C_GREEN}ok{utils.C_WHITE}' if ok else f'{utils.C_RED}FAIL{utils.C_WHITE}'
        if not ok:
            failed += 1
        utils.echo(f'  {name:<10} {flag}  {value}')
    utils.echo()
    if failed:
        utils.error(f'{failed} check(s) failed')
    else:
        utils.info('all checks passed — no third-party packages required')
    return 1 if failed else 0


def cmd_scenarios(args) -> int:
    for item in scenarios.list_scenarios():
        utils.echo(f'  {item["id"]:<12} {item.get("name", "")}')
        utils.echo(f'{utils.C_DIM}      {item.get("description", "")}{utils.C_WHITE}')
    return 0


def cmd_purge_expired(args) -> int:
    settings = config.Settings.load()
    days = args.days if args.days is not None else settings.privacy.retention_days
    removed = store.purge_expired(days)
    utils.info(f'{removed} event(s) older than {days} days deleted')
    return 0


def _iso_in_days(days: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat(timespec='seconds')


if __name__ == '__main__':
    sys.exit(main())
