"""Metrics and exports.

Awareness programmes are measured, not collected.  The numbers here answer the
question a security manager actually asks - "how many of my people would have
handed over their location, and how many reported the page?" - and deliberately
avoid producing a dossier of individuals.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict, Iterable, List, Optional

from . import i18n, privacy, store, utils

#: Event types that make up the simulation funnel, in order.
FUNNEL = ('open', 'consent_prompt', 'consent', 'location', 'report', 'reveal')


def funnel(campaign_id: Optional[str] = None) -> Dict[str, Any]:
    counts = store.count_events(campaign_id)
    recipients = len(store.list_recipients(campaign_id)) if campaign_id else sum(
        len(store.list_recipients(c['id'])) for c in store.list_campaigns()
    )
    opened = counts.get('open', 0)
    prompted = counts.get('consent_prompt', 0)
    shared = counts.get('location', 0)
    reported = counts.get('report', 0)
    revealed = counts.get('reveal', 0)
    denied = _count_decisions(campaign_id, 'denied')
    granted = _count_decisions(campaign_id, 'granted')

    return {
        'links_issued': recipients,
        'opened': opened,
        'prompted': prompted,
        'consent_granted': granted,
        'consent_denied': denied,
        'shared_location': shared,
        'reported': reported,
        'revealed': revealed,
        'errors': counts.get('error', 0),
        'open_rate': utils.pct(opened, recipients),
        'share_rate': utils.pct(shared, opened),
        'report_rate': utils.pct(reported, opened),
        'decline_rate': utils.pct(denied, granted + denied),
        'susceptibility': _susceptibility(shared, denied, opened),
    }


def _count_decisions(campaign_id: Optional[str], decision: str) -> int:
    rows = store.events(campaign_id=campaign_id, limit=5000)
    return sum(1 for r in rows if r['type'] == 'consent'
               and (r.get('payload') or {}).get('decision') == decision)


def _susceptibility(shared: int, denied: int, opened: int) -> int:
    """0 (nobody would fall for it) .. 100 (everybody did)."""
    if not opened:
        return 0
    base = utils.pct(shared, opened)
    # credit the people who actively refused
    adjusted = max(0.0, base - utils.pct(denied, opened) * 0.25)
    return int(round(min(100, adjusted)))


def group_breakdown(campaign_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per-group funnel.  Groups are labels like "finance" or "interns"."""
    rows = store.events(campaign_id=campaign_id, limit=5000)
    rid_to_group: Dict[str, str] = {}
    for campaign in store.list_campaigns():
        for recipient in store.list_recipients(campaign['id']):
            rid_to_group[recipient['rid']] = recipient.get('grp') or 'unassigned'
    buckets: Dict[str, Dict[str, int]] = {}
    for row in rows:
        grp = rid_to_group.get(row.get('rid') or '', 'unassigned')
        bucket = buckets.setdefault(grp, {'opened': 0, 'shared': 0, 'denied': 0, 'reported': 0})
        etype = row['type']
        if etype == 'open':
            bucket['opened'] += 1
        elif etype == 'location':
            bucket['shared'] += 1
        elif etype == 'report':
            bucket['reported'] += 1
        elif etype == 'consent' and (row.get('payload') or {}).get('decision') == 'denied':
            bucket['denied'] += 1
    out = []
    for grp, values in sorted(buckets.items()):
        out.append({
            'group': grp,
            **values,
            'share_rate': utils.pct(values['shared'], values['opened']),
            'report_rate': utils.pct(values['reported'], values['opened']),
        })
    return out


# ----------------------------------------------------------------------
# exports
# ----------------------------------------------------------------------
def events_to_csv(rows: Iterable[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['seq', 'timestamp', 'campaign', 'recipient', 'session', 'type', 'payload'])
    for row in rows:
        writer.writerow([
            row.get('seq'), row.get('ts'), row.get('campaign_id'), row.get('rid'),
            row.get('session_id'), row.get('type'),
            json.dumps(row.get('payload') or {}, ensure_ascii=False),
        ])
    return buf.getvalue()


def campaign_to_csv(campaign_id: str) -> str:
    return events_to_csv(sorted(store.events(campaign_id, limit=100000),
                                key=lambda r: r['seq']))


def campaign_to_json(campaign_id: str) -> str:
    campaign = store.campaign_row_to_dict(store.get_campaign(campaign_id))
    return json.dumps(
        {
            'campaign': {k: v for k, v in campaign.items() if k != 'authz'},
            'funnel': funnel(campaign_id),
            'groups': group_breakdown(campaign_id),
            'consent': store.consent_rows(campaign_id),
            'events': sorted(store.events(campaign_id, limit=100000), key=lambda r: r['seq']),
            'chain': store.verify_chain(),
        },
        ensure_ascii=False,
        indent=2,
    )


KML_HEAD = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>{name}</name>
<Style id="p"><IconStyle><scale>0.7</scale><Icon><href>http://maps.google.com/mapfiles/kml/pushpin/ylw-pushpin.png</href></Icon></IconStyle></Style>
"""
KML_POINT = """<Placemark><name>{label}</name><description>{desc}</description><styleUrl>#p</styleUrl>
<Point><coordinates>{lon},{lat},0</coordinates></Point></Placemark>
"""
KML_TAIL = '</Document></kml>\n'


def campaign_to_kml(campaign_id: str) -> str:
    """Export the *degraded* points only.

    If the policy said "store a geohash tile", the KML contains tile centres -
    exporting more precision than was stored would silently undo the policy.
    """
    campaign = store.campaign_row_to_dict(store.get_campaign(campaign_id))
    name = html.escape(campaign.get('name') or campaign_id)
    out = [KML_HEAD.format(name=name)]
    points = 0
    for row in store.events(campaign_id, limit=100000):
        if row['type'] != 'location':
            continue
        payload = row.get('payload') or {}
        lat, lon = payload.get('lat'), payload.get('lon')
        if lat is None and payload.get('geohash'):
            lat, lon = privacy.geohash_center(payload['geohash'])
        if lat is None or lon is None:
            continue
        out.append(KML_POINT.format(
            label=html.escape(str(row.get('rid') or 'target')),
            desc=html.escape(f"{payload.get('precision', 'reduced')} precision"),
            lon=lon, lat=lat,
        ))
        points += 1
    out.append(KML_TAIL)
    if not points:
        out.insert(1, '<!-- no coordinates stored under the current privacy policy -->\n')
    return ''.join(out)


# ----------------------------------------------------------------------
# HTML report
# ----------------------------------------------------------------------
def html_report(campaign_id: str, lang: str = 'ar') -> str:
    campaign = store.campaign_row_to_dict(store.get_campaign(campaign_id))
    metrics = funnel(campaign_id)
    groups = group_breakdown(campaign_id)
    t = (lambda key, **kw: i18n.t(key, lang, **kw))
    dir_attr = 'rtl' if i18n.is_rtl(lang) else 'ltr'

    def bar(value: int, total: int) -> str:
        width = utils.pct(value, total)
        return (f'<div class="bar"><span style="width:{max(2, width)}%"></span>'
                f'<em>{value}</em></div>')

    rows = ''.join(
        f"<tr><td>{html.escape(str(g['group']))}</td><td>{g['opened']}</td>"
        f"<td>{g['shared']}</td><td>{g['reported']}</td>"
        f"<td>{g['share_rate']}%</td><td>{g['report_rate']}%</td></tr>"
        for g in groups
    ) or f'<tr><td colspan="6">{t("no_events")}</td></tr>'

    total = max(1, metrics['opened'])
    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{dir_attr}"><head><meta charset="utf-8">
<title>{html.escape(campaign.get('name', campaign_id))} · Seeker</title>
<style>
 body{{font-family:system-ui,"Segoe UI","Noto Kufi Arabic",Tahoma,sans-serif;background:#0b1220;
 color:#e5e7eb;margin:0;padding:32px;line-height:1.7}}
 .wrap{{max-width:860px;margin:auto}}
 h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#94a3b8;font-size:13px;margin:0 0 26px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:26px}}
 .card{{background:#0f172a;border:1px solid #1f2937;border-radius:14px;padding:16px}}
 .card b{{display:block;font-size:26px}} .card span{{color:#94a3b8;font-size:12px}}
 .bar{{background:#13233a;border-radius:6px;height:22px;position:relative;overflow:hidden}}
 .bar span{{display:block;height:100%;background:linear-gradient(90deg,#0ea5e9,#22d3ee)}}
 .bar em{{position:absolute;inset-inline-end:8px;top:2px;font-style:normal;font-size:12px;color:#cbd5e1}}
 ul{{margin:0;padding-inline-start:20px}} li{{margin:6px 0}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:start;padding:9px 10px;border-bottom:1px solid #1f2937}}
 th{{color:#94a3b8;font-weight:600;font-size:12px}}
 footer{{margin-top:30px;color:#475569;font-size:11.5px}}
</style></head><body><div class="wrap">
<h1>{html.escape(campaign.get('name', campaign_id))}</h1>
<p class="sub">{html.escape(str(campaign.get('purpose') or ''))} ·
{html.escape(str(campaign.get('authorizer') or ''))} ·
{html.escape(str(campaign.get('scope') or ''))}</p>
<div class="grid">
 <div class="card"><b>{metrics['links_issued']}</b><span>{t('sent')}</span></div>
 <div class="card"><b>{metrics['opened']}</b><span>{t('opened')} · {metrics['open_rate']}%</span></div>
 <div class="card"><b>{metrics['shared_location']}</b><span>{t('consented')}</span></div>
 <div class="card"><b>{metrics['consent_denied']}</b><span>{t('declined')}</span></div>
 <div class="card"><b>{metrics['reported']}</b><span>{t('reported')}</span></div>
 <div class="card"><b>{metrics['susceptibility']}</b><span>{t('risk_score')}</span></div>
</div>
<h3>{t('dash_funnel')}</h3>
<ul>
<li>{t('opened')}: {bar(metrics['opened'], max(1, metrics['links_issued']))}</li>
<li>{t('consented')}: {bar(metrics['shared_location'], total)}</li>
<li>{t('declined')}: {bar(metrics['consent_denied'], total)}</li>
<li>{t('reported')}: {bar(metrics['reported'], total)}</li>
<li>{t('revealed')}: {bar(metrics['revealed'], total)}</li>
</ul>
<h3>{t('dash_campaigns')} · groups</h3>
<table><thead><tr><th>group</th><th>{t('opened')}</th><th>{t('consented')}</th>
<th>{t('reported')}</th><th>{t('share_rate')}</th><th>{t('report_rate')}</th></tr></thead>
<tbody>{rows}</tbody></table>
<footer>Seeker · precision <b>{html.escape(str((campaign.get('privacy') or {}).get('precision', 'geohash')))}
</b> · retention {html.escape(str((campaign.get('privacy') or {}).get('retention_days', 30)))} days
· generated {utils.now_iso()}</footer>
</div></body></html>"""
