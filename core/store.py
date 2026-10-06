"""SQLite storage layer with a tamper-evident (hash-chained) event log.

Replaces the v1 design where PHP wrote two flat text files that Python polled
every two seconds.  That design lost data whenever two people hit the page at
the same time, and it could pair one person's device telemetry with another
person's coordinates.  Here every event carries a session id and the log is a
hash chain, so tampering or accidental truncation is detectable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from . import config, utils

_local = threading.local()
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    scenario        TEXT NOT NULL,
    lang            TEXT DEFAULT 'ar',
    authorizer      TEXT,
    scope           TEXT,
    purpose         TEXT,
    created_at      TEXT NOT NULL,
    expires_at      TEXT,
    status          TEXT DEFAULT 'active',
    privacy         TEXT NOT NULL,
    authz           TEXT,
    notice_version  TEXT DEFAULT '1.0'
);

CREATE TABLE IF NOT EXISTS recipients (
    rid          TEXT PRIMARY KEY,
    campaign_id  TEXT NOT NULL,
    label        TEXT,
    grp          TEXT,
    token        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns (id)
);

CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    campaign_id  TEXT,
    rid          TEXT,
    session_id   TEXT,
    type         TEXT NOT NULL,
    payload      TEXT,
    prev_hash    TEXT,
    row_hash     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consent_ledger (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    campaign_id     TEXT,
    rid             TEXT,
    session_id      TEXT,
    notice_version  TEXT NOT NULL,
    notice_hash     TEXT NOT NULL,
    decision        TEXT NOT NULL,
    purpose         TEXT,
    retention_days  INTEGER,
    subject_hash    TEXT,
    signature       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_runs (
    id          TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    target      TEXT,
    score       INTEGER,
    verdict     TEXT,
    findings    TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_campaign ON events (campaign_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);
CREATE INDEX IF NOT EXISTS idx_recipients_campaign ON recipients (campaign_id);
"""


def db_path() -> str:
    return os.path.join(config.data_dir(), 'seeker.db')


def connect() -> sqlite3.Connection:
    conn = getattr(_local, 'conn', None)
    if conn is None:
        conn = sqlite3.connect(db_path(), timeout=15, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA foreign_keys=ON')
        _local.conn = conn
    return conn


@contextmanager
def tx():
    conn = connect()
    with _lock:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def init_db():
    os.makedirs(config.data_dir(), exist_ok=True)
    conn = connect()
    with _lock:
        conn.executescript(SCHEMA)
        conn.commit()
    return db_path()


def close():
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        conn.close()
        _local.conn = None


# ----------------------------------------------------------------------
# hash chain helpers
# ----------------------------------------------------------------------
GENESIS = '0' * 64


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute('SELECT row_hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
    return row['row_hash'] if row else GENESIS


def _row_hash(prev: str, ts: str, campaign_id: str, rid: str, session: str,
              etype: str, payload: str) -> str:
    blob = '|'.join([prev, ts, str(campaign_id or ''), str(rid or ''),
                     str(session or ''), etype, str(payload or '')])
    return utils.sha256(blob)


def append_event(campaign_id: Optional[str], rid: Optional[str], session_id: Optional[str],
                 etype: str, payload: Optional[dict] = None, ts: Optional[str] = None) -> Dict[str, Any]:
    """Append one event and return the stored row."""
    ts = ts or utils.now_iso()
    payload_json = json.dumps(payload or {}, ensure_ascii=False, sort_keys=True)
    with tx() as conn:
        prev = _last_hash(conn)
        digest = _row_hash(prev, ts, campaign_id, rid, session_id, etype, payload_json)
        cur = conn.execute(
            'INSERT INTO events (ts, campaign_id, rid, session_id, type, payload, prev_hash, row_hash)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (ts, campaign_id, rid, session_id, etype, payload_json, prev, digest),
        )
        seq = cur.lastrowid
    return {
        'seq': seq, 'ts': ts, 'campaign_id': campaign_id, 'rid': rid,
        'session_id': session_id, 'type': etype, 'payload': payload or {},
    }


def verify_chain() -> Dict[str, Any]:
    """Walk the whole log and confirm every link still hashes correctly."""
    conn = connect()
    rows = conn.execute('SELECT * FROM events ORDER BY seq').fetchall()
    prev = GENESIS
    broken = None
    for row in rows:
        expected = _row_hash(prev, row['ts'], row['campaign_id'], row['rid'],
                             row['session_id'], row['type'], row['payload'])
        if expected != row['row_hash']:
            broken = row['seq']
            break
        prev = row['row_hash']
    return {'ok': broken is None, 'events': len(rows), 'broken_at': broken}


# ----------------------------------------------------------------------
# campaigns
# ----------------------------------------------------------------------
def create_campaign(**fields) -> str:
    cid = fields.get('id') or utils.secrets_hex(6)
    privacy = fields.get('privacy') or {}
    with tx() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO campaigns'
            ' (id, name, scenario, lang, authorizer, scope, purpose, created_at, expires_at,'
            '  status, privacy, authz, notice_version)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                cid,
                fields.get('name') or 'Untitled campaign',
                fields.get('scenario') or 'delivery',
                fields.get('lang') or 'ar',
                fields.get('authorizer'),
                fields.get('scope'),
                fields.get('purpose'),
                fields.get('created_at') or utils.now_iso(),
                fields.get('expires_at'),
                fields.get('status') or 'active',
                json.dumps(privacy if isinstance(privacy, dict) else privacy.__dict__,
                           ensure_ascii=False),
                json.dumps(fields.get('authz') or {}, ensure_ascii=False),
                fields.get('notice_version') or '1.0',
            ),
        )
    return cid


def get_campaign(cid: str) -> Optional[sqlite3.Row]:
    return connect().execute('SELECT * FROM campaigns WHERE id = ?', (cid,)).fetchone()


def campaign_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    if row is None:
        return {}
    data = dict(row)
    for key in ('privacy', 'authz'):
        try:
            data[key] = json.loads(data.get(key) or '{}')
        except json.JSONDecodeError:
            data[key] = {}
    return data


def list_campaigns() -> List[Dict[str, Any]]:
    rows = connect().execute('SELECT * FROM campaigns ORDER BY created_at DESC').fetchall()
    return [campaign_row_to_dict(r) for r in rows]


def set_campaign_status(cid: str, status: str):
    with tx() as conn:
        conn.execute('UPDATE campaigns SET status = ? WHERE id = ?', (status, cid))


def expire_stale_campaigns() -> int:
    """Flip campaigns whose authorisation window has passed to 'expired'."""
    now = utils.now_iso()
    with tx() as conn:
        cur = conn.execute(
            "UPDATE campaigns SET status = 'expired'"
            " WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?",
            (now,),
        )
        return cur.rowcount


# ----------------------------------------------------------------------
# recipients / tracking links
# ----------------------------------------------------------------------
def add_recipients(campaign_id: str, entries: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    created = []
    with tx() as conn:
        for entry in entries:
            rid = entry.get('rid') or utils.secrets_hex(6)
            token = entry.get('token') or utils.secrets_hex(9)
            conn.execute(
                'INSERT OR REPLACE INTO recipients (rid, campaign_id, label, grp, token, created_at)'
                ' VALUES (?, ?, ?, ?, ?, ?)',
                (rid, campaign_id, entry.get('label'), entry.get('group'), token, utils.now_iso()),
            )
            created.append({'rid': rid, 'token': token, 'label': entry.get('label'),
                            'group': entry.get('group')})
    return created


def list_recipients(campaign_id: str) -> List[Dict[str, Any]]:
    rows = connect().execute(
        'SELECT * FROM recipients WHERE campaign_id = ? ORDER BY created_at', (campaign_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def resolve_token(token: str) -> Optional[Dict[str, Any]]:
    row = connect().execute('SELECT * FROM recipients WHERE token = ?', (token,)).fetchone()
    return dict(row) if row else None


# ----------------------------------------------------------------------
# reads
# ----------------------------------------------------------------------
def events(campaign_id: Optional[str] = None, since_seq: int = 0,
           limit: int = 500) -> List[Dict[str, Any]]:
    conn = connect()
    sql = 'SELECT * FROM events WHERE seq > ?'
    args: List[Any] = [since_seq]
    if campaign_id:
        sql += ' AND campaign_id = ?'
        args.append(campaign_id)
    sql += ' ORDER BY seq DESC LIMIT ?'
    args.append(limit)
    rows = conn.execute(sql, args).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item['payload'] = json.loads(item['payload'] or '{}')
        except json.JSONDecodeError:
            item['payload'] = {}
        out.append(item)
    return out


def count_events(campaign_id: Optional[str] = None) -> Dict[str, int]:
    conn = connect()
    sql = 'SELECT type, COUNT(*) AS n FROM events'
    args: list = []
    if campaign_id:
        sql += ' WHERE campaign_id = ?'
        args.append(campaign_id)
    sql += ' GROUP BY type'
    return {row['type']: row['n'] for row in conn.execute(sql, args)}


def purge_expired(retention_days: int) -> int:
    """Delete events older than the retention window (data-minimisation)."""
    cutoff = utils and _retention_cutoff(retention_days)
    if not cutoff:
        return 0
    with tx() as conn:
        cur = conn.execute('DELETE FROM events WHERE ts < ?', (cutoff,))
        return cur.rowcount


def _retention_cutoff(days: int):
    from .privacy import retention_cutoff_iso

    return retention_cutoff_iso(days)


def purge_campaign(campaign_id: str) -> int:
    with tx() as conn:
        conn.execute('DELETE FROM events WHERE campaign_id = ?', (campaign_id,))
        conn.execute('DELETE FROM consent_ledger WHERE campaign_id = ?', (campaign_id,))
        conn.execute('DELETE FROM recipients WHERE campaign_id = ?', (campaign_id,))
        cur = conn.execute('DELETE FROM campaigns WHERE id = ?', (campaign_id,))
        return cur.rowcount


# ----------------------------------------------------------------------
# consent ledger
# ----------------------------------------------------------------------
def record_consent(campaign_id, rid, session_id, notice_version: str, notice_text: str,
                   decision: str, purpose: str, retention_days: int,
                   subject_hash: str, secret: str) -> int:
    ts = utils.now_iso()
    notice_hash = utils.sha256(notice_text)
    signature = utils.hmac_sign(
        secret, f'{ts}|{campaign_id}|{rid}|{session_id}|{notice_hash}|{decision}'
    )
    with tx() as conn:
        cur = conn.execute(
            'INSERT INTO consent_ledger (ts, campaign_id, rid, session_id, notice_version,'
            ' notice_hash, decision, purpose, retention_days, subject_hash, signature)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (ts, campaign_id, rid, session_id, notice_version, notice_hash, decision,
             purpose, retention_days, subject_hash, signature),
        )
        return cur.lastrowid


def consent_rows(campaign_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = connect()
    if campaign_id:
        rows = conn.execute(
            'SELECT * FROM consent_ledger WHERE campaign_id = ? ORDER BY id', (campaign_id,)
        ).fetchall()
    else:
        rows = conn.execute('SELECT * FROM consent_ledger ORDER BY id').fetchall()
    return [dict(r) for r in rows]


def verify_consent(secret: str) -> Dict[str, Any]:
    rows = consent_rows()
    bad = []
    for row in rows:
        expected = utils.hmac_sign(
            secret,
            f"{row['ts']}|{row['campaign_id']}|{row['rid']}|{row['session_id']}|"
            f"{row['notice_hash']}|{row['decision']}",
        )
        if expected != row['signature']:
            bad.append(row['id'])
    return {'ok': not bad, 'records': len(rows), 'invalid': bad}


# ----------------------------------------------------------------------
# audit runs
# ----------------------------------------------------------------------
def save_audit(run_id: str, target: str, score: int, verdict: str, findings: list):
    with tx() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO audit_runs (id, ts, target, score, verdict, findings)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (run_id, utils.now_iso(), target, score, verdict,
             json.dumps(findings, ensure_ascii=False)),
        )


def list_audits(limit: int = 20) -> List[Dict[str, Any]]:
    rows = connect().execute(
        'SELECT * FROM audit_runs ORDER BY ts DESC LIMIT ?', (limit,)
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item['findings'] = json.loads(item['findings'] or '[]')
        except json.JSONDecodeError:
            item['findings'] = []
        out.append(item)
    return out
