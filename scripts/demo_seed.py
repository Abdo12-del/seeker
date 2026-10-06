#!/usr/bin/env python3
"""Seed a demo campaign with synthetic events.

Useful for a workshop, a screenshot or a CI smoke test.  Everything it writes
is fake and labelled as such: no real person is ever targeted by this script.

    python3 scripts/demo_seed.py --people 24
"""

from __future__ import annotations

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import authz, config, privacy, store, utils  # noqa: E402

GROUPS = ('finance', 'engineering', 'interns')
DEVICES = (
    {'os': 'Android 13', 'platform': 'Linux armv8l', 'browser': 'Chrome/120',
     'cores': '8', 'ram': '6', 'screen': '1080x2340'},
    {'os': 'Windows NT 10.0', 'platform': 'Win32', 'browser': 'Edg/119',
     'cores': '12', 'ram': '16', 'screen': '1920x1080'},
    {'os': 'iPhone', 'platform': 'iPhone', 'browser': 'Safari/17',
     'cores': '6', 'ram': '4', 'screen': '390x844'},
)
CITIES = {
    'finance': (33.3681, 6.8607),
    'engineering': (36.7538, 3.0588),
    'interns': (35.6991, -0.6359),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--people', type=int, default=24)
    parser.add_argument('--name', default='Q4 awareness baseline')
    parser.add_argument('--scenario', default='delivery')
    parser.add_argument('--lang', default='ar')
    args = parser.parse_args(argv)

    config.data_dir()
    store.init_db()

    cid = utils.secrets_hex(6)
    expires = authz_expiry(30)
    record = authz.build_authz(
        cid, 'Demo trainer', 'demo workspace — synthetic data only',
        'workshop demonstration', expires,
    )
    store.create_campaign(
        id=cid, name=args.name, scenario=args.scenario, lang=args.lang,
        authorizer='Demo trainer', scope='demo workspace — synthetic data only',
        purpose='workshop demonstration', expires_at=expires,
        privacy=config.Settings.load().privacy.__dict__.copy(), authz=record,
    )

    recipients = store.add_recipients(cid, [
        {'label': f'person-{i:02d}', 'group': GROUPS[i % len(GROUPS)]}
        for i in range(max(1, args.people))
    ])

    random.seed(7)
    for index, recipient in enumerate(recipients):
        session = utils.secrets_hex(6)
        group = recipient['group'] or 'unassigned'
        base_lat, base_lon = CITIES.get(group, (0.0, 0.0))
        device = random.choice(DEVICES)

        # not everybody opens the link
        if index % 8 == 3:
            continue
        store.append_event(cid, recipient['rid'], session, 'device', dict(device))
        store.append_event(cid, recipient['rid'], session, 'open', {})
        store.append_event(cid, recipient['rid'], session, 'consent_prompt', {})

        # roughly a third decline, a tenth report the page
        roll = random.random()
        if roll < 0.12:
            store.append_event(cid, recipient['rid'], session, 'report',
                               {'reason': 'asked for my location out of nowhere'})
            store.append_event(cid, recipient['rid'], session, 'reveal', {'shared': False})
            continue
        if roll < 0.42:
            store.append_event(cid, recipient['rid'], session, 'consent', {'decision': 'denied'})
            store.append_event(cid, recipient['rid'], session, 'reveal', {'shared': False})
            continue

        store.append_event(cid, recipient['rid'], session, 'consent', {'decision': 'granted'})
        lat = base_lat + random.uniform(-0.05, 0.05)
        lon = base_lon + random.uniform(-0.05, 0.05)
        policy = config.Settings.load().privacy
        store.append_event(cid, recipient['rid'], session, 'location',
                           privacy.degrade_location(lat, lon, random.randint(5, 60), policy))
        store.append_event(cid, recipient['rid'], session, 'reveal', {'shared': True})

    from core import reporting

    print(f'campaign {cid} seeded with {len(recipients)} synthetic recipients')
    for key, value in reporting.funnel(cid).items():
        print(f'  {key:<18} {value}')
    print(f'\nconsole : http://127.0.0.1:8080/console')
    print(f'link    : /l/{recipients[0]["token"]}')
    return 0


def authz_expiry(days: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')


if __name__ == '__main__':
    sys.exit(main())
