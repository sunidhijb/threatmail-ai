import sqlite3
import json
import os
import logging
from datetime import datetime

log = logging.getLogger(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'threatmail.db')


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        client_name TEXT,
        escalation_type TEXT,
        severity TEXT,
        platform_affected TEXT,
        pillar_affected TEXT,
        ticket_reference TEXT,
        assets TEXT,
        detection_issue TEXT,
        escalation_summary TEXT,
        threat_classification TEXT,
        rca_problem_statement TEXT,
        rca_root_cause TEXT,
        rca_executive_summary TEXT,
        status TEXT DEFAULT "RCA Generated",
        notes TEXT,
        email_text TEXT,
        full_result TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS takedowns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        escalation_id INTEGER,
        asset TEXT NOT NULL,
        asset_type TEXT,
        submitted_at TEXT,
        status TEXT DEFAULT "Submitted",
        last_checked TEXT,
        resolved_at TEXT,
        notes TEXT,
        vt_verdict TEXT,
        FOREIGN KEY(escalation_id) REFERENCES escalations(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS gap_library (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        escalation_type TEXT,
        platform TEXT,
        gap_title TEXT,
        detection_gap_explanation TEXT,
        platform_constraints TEXT,
        usage_count INTEGER DEFAULT 1,
        tags TEXT
    )''')
    conn.commit()
    conn.close()
    log.info("Database initialized")


def save_escalation(result: dict) -> int:
    conn = get_conn()
    c = conn.cursor()
    esc = result.get('escalation_summary', {})
    inv = result.get('investigation', {})
    rca = result.get('rca', {})
    cause = rca.get('cause_and_effect', {})

    c.execute('''INSERT INTO escalations (
        created_at, client_name, escalation_type, severity,
        platform_affected, pillar_affected, ticket_reference, assets,
        detection_issue, escalation_summary, threat_classification,
        rca_problem_statement, rca_root_cause, rca_executive_summary,
        status, email_text, full_result
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
        result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        esc.get('brand_targeted', 'Unknown'),
        esc.get('escalation_type', 'other'),
        esc.get('severity', 'High'),
        esc.get('platform_affected', ''),
        esc.get('pillar_affected', ''),
        esc.get('ticket_reference', ''),
        json.dumps(esc.get('assets_extracted', [])),
        esc.get('detection_issue', ''),
        esc.get('escalation_summary', ''),
        inv.get('threat_classification', ''),
        rca.get('problem_statement', ''),
        cause.get('root_cause', ''),
        rca.get('executive_summary', ''),
        'RCA Generated',
        result.get('email_text', '')[:5000],
        json.dumps(result)
    ))
    eid = c.lastrowid

    # Auto-save to gap library
    gap = cause.get('detection_gap_explanation', '')
    if gap:
        c.execute('''INSERT INTO gap_library (
            created_at, escalation_type, platform, gap_title,
            detection_gap_explanation, platform_constraints, tags
        ) VALUES (?,?,?,?,?,?,?)''', (
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            esc.get('escalation_type', ''),
            esc.get('platform_affected', ''),
            f"{esc.get('escalation_type', 'other').replace('_', ' ').title()} — {esc.get('platform_affected', '')}",
            gap,
            cause.get('platform_constraints', ''),
            json.dumps([esc.get('escalation_type', ''), esc.get('platform_affected', '')])
        ))

    conn.commit()
    conn.close()
    return eid


def get_all_escalations():
    conn = get_conn()
    rows = conn.execute('SELECT * FROM escalations ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_escalation(eid: int):
    conn = get_conn()
    row = conn.execute('SELECT * FROM escalations WHERE id=?', (eid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_escalation_status(eid: int, status: str, notes: str = None):
    conn = get_conn()
    if notes:
        conn.execute('UPDATE escalations SET status=?, notes=? WHERE id=?', (status, notes, eid))
    else:
        conn.execute('UPDATE escalations SET status=? WHERE id=?', (status, eid))
    conn.commit()
    conn.close()


def save_takedown(escalation_id, asset, asset_type, vt_verdict=None):
    conn = get_conn()
    conn.execute(
        'INSERT INTO takedowns (escalation_id,asset,asset_type,submitted_at,status,vt_verdict) VALUES (?,?,?,?,?,?)',
        (escalation_id, asset, asset_type, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Submitted', vt_verdict)
    )
    conn.commit()
    conn.close()


def get_all_takedowns():
    conn = get_conn()
    rows = conn.execute('''SELECT t.*, e.client_name, e.created_at as escalation_date
        FROM takedowns t LEFT JOIN escalations e ON t.escalation_id=e.id
        ORDER BY t.submitted_at DESC''').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_takedown(tid: int, status: str, notes: str = None):
    conn = get_conn()
    updates = {'status': status, 'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    if status == 'Taken Down':
        updates['resolved_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if notes:
        updates['notes'] = notes
    s = ', '.join(f"{k}=?" for k in updates)
    conn.execute(f'UPDATE takedowns SET {s} WHERE id=?', (*updates.values(), tid))
    conn.commit()
    conn.close()


def get_gap_library():
    conn = get_conn()
    rows = conn.execute('SELECT * FROM gap_library ORDER BY usage_count DESC, created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]


def increment_gap_usage(gid: int):
    conn = get_conn()
    conn.execute('UPDATE gap_library SET usage_count=usage_count+1 WHERE id=?', (gid,))
    conn.commit()
    conn.close()


def get_dashboard_stats():
    conn = get_conn()
    total = conn.execute('SELECT COUNT(*) as c FROM escalations').fetchone()['c']
    by_severity = conn.execute('SELECT severity, COUNT(*) as c FROM escalations GROUP BY severity').fetchall()
    by_type = conn.execute('SELECT escalation_type, COUNT(*) as c FROM escalations GROUP BY escalation_type ORDER BY c DESC LIMIT 8').fetchall()
    by_client = conn.execute('SELECT client_name, COUNT(*) as c FROM escalations GROUP BY client_name ORDER BY c DESC LIMIT 10').fetchall()
    by_status = conn.execute('SELECT status, COUNT(*) as c FROM escalations GROUP BY status').fetchall()
    by_platform = conn.execute('SELECT platform_affected, COUNT(*) as c FROM escalations GROUP BY platform_affected ORDER BY c DESC LIMIT 6').fetchall()
    recent = conn.execute('SELECT id, client_name, escalation_type, severity, status, created_at FROM escalations ORDER BY created_at DESC LIMIT 5').fetchall()
    monthly = conn.execute("SELECT substr(created_at,1,7) as month, COUNT(*) as c FROM escalations GROUP BY month ORDER BY month ASC LIMIT 12").fetchall()
    open_td = conn.execute("SELECT COUNT(*) as c FROM takedowns WHERE status NOT IN ('Taken Down','Failed')").fetchone()['c']
    gap_count = conn.execute("SELECT COUNT(*) as c FROM gap_library").fetchone()['c']
    conn.close()
    return {
        'total': total,
        'by_severity': [dict(r) for r in by_severity],
        'by_type': [dict(r) for r in by_type],
        'by_client': [dict(r) for r in by_client],
        'by_status': [dict(r) for r in by_status],
        'by_platform': [dict(r) for r in by_platform],
        'recent': [dict(r) for r in recent],
        'monthly': [dict(r) for r in monthly],
        'open_takedowns': open_td,
        'gap_count': gap_count,
    }
