import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.environ.get("NETSHIELD_DB_PATH", os.path.join(os.path.dirname(__file__), "netshield.db"))

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL COLLATE NOCASE,
        reason TEXT DEFAULT 'Acesso não autorizado pelas regras de segurança',
        category TEXT DEFAULT 'Geral',
        enabled INTEGER DEFAULT 1,
        hits INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS query_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_ip TEXT NOT NULL,
        domain TEXT NOT NULL,
        query_type TEXT DEFAULT 'A',
        status TEXT NOT NULL,
        timestamp TEXT NOT NULL
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS unblock_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING',
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)

    # Default settings
    default_settings = [
        ("server_ip", "192.168.1.100"),
        ("upstream_dns", "1.1.1.1, 8.8.8.8"),
        ("block_message_default", "Este site foi bloqueado de acordo com a política de segurança e controle de conteúdo da rede."),
        ("admin_contact", "suporte@rede.local"),
        ("enable_logging", "1")
    ]
    for key, value in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (key, value))

    # Seed initial useful blocked domains if empty
    cursor.execute("SELECT COUNT(*) FROM blocked_domains;")
    count = cursor.fetchone()[0]
    if count == 0:
        initial_blocks = [
            ("tiktok.com", "Conteúdo não autorizado durante o expediente", "Redes Sociais"),
            ("www.tiktok.com", "Conteúdo não autorizado durante o expediente", "Redes Sociais"),
            ("bet365.com", "Jogos de aposta e cassino online proibidos na rede", "Apostas"),
            ("blaze.com", "Jogos de aposta e cassino online proibidos na rede", "Apostas"),
            ("xvideos.com", "Conteúdo adulto e impróprio restrito pela política", "Adulto"),
            ("pornhub.com", "Conteúdo adulto e impróprio restrito pela política", "Adulto"),
            ("torrentz2eu.org", "Downloads P2P e compartilhamento ilegal de arquivos", "P2P / Torrent"),
        ]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for domain, reason, cat in initial_blocks:
            cursor.execute(
                "INSERT INTO blocked_domains (domain, reason, category, enabled, hits, created_at) VALUES (?, ?, ?, 1, 0, ?);",
                (domain.lower(), reason, cat, now)
            )

    conn.commit()
    conn.close()

# Operations for blocked_domains
def list_blocked_domains(search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    if search:
        query = "%" + search.strip().lower() + "%"
        cursor.execute("SELECT * FROM blocked_domains WHERE domain LIKE ? OR reason LIKE ? OR category LIKE ? ORDER BY id DESC;", (query, query, query))
    else:
        cursor.execute("SELECT * FROM blocked_domains ORDER BY id DESC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_blocked_domain_info(domain: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    clean_domain = domain.strip().lower()
    cursor.execute("SELECT * FROM blocked_domains WHERE domain = ? AND enabled = 1 LIMIT 1;", (clean_domain,))
    row = cursor.fetchone()
    if not row:
        # Check without www or with www
        if clean_domain.startswith("www."):
            cursor.execute("SELECT * FROM blocked_domains WHERE domain = ? AND enabled = 1 LIMIT 1;", (clean_domain[4:],))
            row = cursor.fetchone()
        else:
            cursor.execute("SELECT * FROM blocked_domains WHERE domain = ? AND enabled = 1 LIMIT 1;", (f"www.{clean_domain}",))
            row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_blocked_domain(domain: str, reason: str, category: str = "Geral") -> bool:
    clean_domain = domain.strip().lower()
    if not clean_domain:
        return False
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cursor.execute(
            "INSERT INTO blocked_domains (domain, reason, category, enabled, hits, created_at) VALUES (?, ?, ?, 1, 0, ?);",
            (clean_domain, reason.strip() or "Bloqueio administrativo", category.strip() or "Geral", now)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success

def toggle_blocked_domain(domain_id: int) -> Optional[int]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM blocked_domains WHERE id = ?;", (domain_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    new_state = 0 if row["enabled"] == 1 else 1
    cursor.execute("UPDATE blocked_domains SET enabled = ? WHERE id = ?;", (new_state, domain_id))
    conn.commit()
    conn.close()
    return new_state

def delete_blocked_domain(domain_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_domains WHERE id = ?;", (domain_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def increment_hits(domain: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocked_domains SET hits = hits + 1 WHERE domain = ?;", (domain.strip().lower(),))
    conn.commit()
    conn.close()

# Operations for Query Logs
def log_query(client_ip: str, domain: str, status: str, query_type: str = "A"):
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO query_logs (client_ip, domain, query_type, status, timestamp) VALUES (?, ?, ?, ?, ?);",
        (client_ip, domain.strip().lower(), query_type, status.upper(), now)
    )
    conn.commit()
    conn.close()

def get_recent_logs(limit: int = 50, filter_status: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM query_logs WHERE 1=1"
    params = []
    if filter_status and filter_status in ["ALLOWED", "BLOCKED"]:
        query += " AND status = ?"
        params.append(filter_status)
    if search:
        query += " AND (domain LIKE ? OR client_ip LIKE ?)"
        s = "%" + search.strip() + "%"
        params.extend([s, s])
    query += " ORDER BY id DESC LIMIT ?;"
    params.append(limit)
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats() -> Dict[str, Any]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM query_logs;")
    total_queries = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM query_logs WHERE status = 'BLOCKED';")
    total_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocked_domains WHERE enabled = 1;")
    active_blocked_domains = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT client_ip) FROM query_logs;")
    unique_clients = cursor.fetchone()[0]

    block_rate = round((total_blocked / total_queries * 100), 1) if total_queries > 0 else 0.0

    # Hourly stats for chart (last 8 hours)
    cursor.execute("""
    SELECT strftime('%H:00', timestamp) as hour,
           SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
           SUM(CASE WHEN status = 'ALLOWED' THEN 1 ELSE 0 END) as allowed
    FROM query_logs
    GROUP BY hour
    ORDER BY hour DESC
    LIMIT 8;
    """)
    chart_data = [dict(row) for row in cursor.fetchall()]
    chart_data.reverse()

    # Top blocked domains
    cursor.execute("""
    SELECT domain, COUNT(*) as count
    FROM query_logs
    WHERE status = 'BLOCKED'
    GROUP BY domain
    ORDER BY count DESC
    LIMIT 5;
    """)
    top_blocked = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total_queries": total_queries,
        "total_blocked": total_blocked,
        "active_blocked_domains": active_blocked_domains,
        "unique_clients": unique_clients,
        "block_rate": block_rate,
        "chart_data": chart_data,
        "top_blocked": top_blocked
    }

# Unblock requests
def create_unblock_request(domain: str, client_ip: str, reason: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO unblock_requests (domain, client_ip, reason, status, created_at) VALUES (?, ?, ?, 'PENDING', ?);",
        (domain.strip().lower(), client_ip, reason.strip(), now)
    )
    conn.commit()
    conn.close()
    return True

def list_unblock_requests() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM unblock_requests ORDER BY id DESC LIMIT 50;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Settings
def get_settings() -> Dict[str, str]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings;")
    rows = cursor.fetchall()
    conn.close()
    return {row["key"]: row["value"] for row in rows}

def update_setting(key: str, value: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?);", (key, value))
    conn.commit()
    conn.close()
