import sqlite3
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

DEFAULT_DB = "/opt/netshield/data/netshield.db" if os.path.isdir("/opt/netshield/data") else os.path.join(os.path.dirname(__file__), "netshield.db")
DB_PATH = os.environ.get("NETSHIELD_DB_PATH", DEFAULT_DB)

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 150000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, salt, hex_hash = stored_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 150000)
        return hmac.compare_digest(dk.hex(), hex_hash)
    except Exception:
        return False

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

    # Commercial SaaS tables: Users, Plans, Clients, Devices
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'client',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        price REAL NOT NULL DEFAULT 0.0,
        duration_days INTEGER NOT NULL DEFAULT 30,
        max_devices INTEGER NOT NULL DEFAULT 2,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        plan_id INTEGER,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'ACTIVE',
        expires_at TEXT NOT NULL,
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (plan_id) REFERENCES plans(id) ON DELETE SET NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        vpn_ip TEXT UNIQUE NOT NULL,
        wg_public_key TEXT NOT NULL,
        wg_private_key TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    );
    """)

    # Default settings
    default_settings = [
        ("server_ip", "192.168.1.100"),
        ("upstream_dns", "1.1.1.1, 8.8.8.8"),
        ("block_message_default", "Este site foi bloqueado de acordo com a política de segurança e controle de conteúdo da rede."),
        ("admin_contact", "suporte@rede.local"),
        ("enable_logging", "1"),
        ("session_secret", secrets.token_hex(32)),
        ("wg_endpoint_port", "51820"),
        ("wg_server_pubkey", "")
    ]
    for key, value in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (key, value))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Seed default Admin user if no admin exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin';")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 'admin', 1, ?);",
            ("admin", "admin@netshield.local", hash_password("admin123"), now)
        )

    # Seed default commercial plans if empty
    cursor.execute("SELECT COUNT(*) FROM plans;")
    if cursor.fetchone()[0] == 0:
        initial_plans = [
            ("Plano Básico", "Proteção DNS + VPN para até 2 dispositivos com bloqueio de anúncios e conteúdo adulto.", 19.90, 30, 2),
            ("Plano Família", "Proteção completa para até 5 dispositivos com controle parental e redes sociais.", 39.90, 30, 5),
            ("Plano Empresarial", "Segurança corporativa avançada para até 15 dispositivos com suporte prioritário.", 99.90, 30, 15),
        ]
        for name, desc, price, days, max_dev in initial_plans:
            cursor.execute(
                "INSERT INTO plans (name, description, price, duration_days, max_devices, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?);",
                (name, desc, price, days, max_dev, now)
            )

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
            ("doubleclick.net", "Rastreador e rede de anúncios bloqueada", "Anúncios & Trackers"),
            ("googlesyndication.com", "Rede de anúncios bloqueada", "Anúncios & Trackers"),
        ]
        for domain, reason, cat in initial_blocks:
            cursor.execute(
                "INSERT INTO blocked_domains (domain, reason, category, enabled, hits, created_at) VALUES (?, ?, ?, 1, 0, ?);",
                (domain.lower(), reason, cat, now)
            )

    conn.commit()
    conn.close()

# ==================== AUTH & USERS ====================

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? LIMIT 1;", (username.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, is_active, created_at FROM users WHERE id = ? LIMIT 1;", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_user_password(user_id: int, new_password: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (hash_password(new_password), user_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

# ==================== PLANS ====================

def list_plans(only_active: bool = False) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    if only_active:
        cursor.execute("SELECT * FROM plans WHERE is_active = 1 ORDER BY price ASC;")
    else:
        cursor.execute("SELECT * FROM plans ORDER BY price ASC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_plan(plan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM plans WHERE id = ?;", (plan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_plan(name: str, description: str, price: float, duration_days: int, max_devices: int) -> Optional[int]:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        cursor.execute(
            "INSERT INTO plans (name, description, price, duration_days, max_devices, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?);",
            (name.strip(), description.strip(), float(price), int(duration_days), int(max_devices), now)
        )
        plan_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        plan_id = None
    finally:
        conn.close()
    return plan_id

def toggle_plan(plan_id: int) -> Optional[int]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active FROM plans WHERE id = ?;", (plan_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    new_val = 0 if row["is_active"] == 1 else 1
    cursor.execute("UPDATE plans SET is_active = ? WHERE id = ?;", (new_val, plan_id))
    conn.commit()
    conn.close()
    return new_val

def delete_plan(plan_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM plans WHERE id = ?;", (plan_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

# ==================== CLIENTS & DEVICES ====================

def refresh_expired_clients() -> int:
    """Marks clients past expires_at as EXPIRED."""
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "UPDATE clients SET status = 'EXPIRED' WHERE status = 'ACTIVE' AND expires_at < ?;",
        (now,)
    )
    changed = cursor.rowcount
    conn.commit()
    conn.close()
    return changed

def list_clients(search: Optional[str] = None) -> List[Dict[str, Any]]:
    refresh_expired_clients()
    conn = get_db()
    cursor = conn.cursor()
    query = """
    SELECT c.*, p.name as plan_name, p.price as plan_price, p.max_devices as max_devices,
           u.username as username,
           (SELECT COUNT(*) FROM devices d WHERE d.client_id = c.id AND d.is_active = 1) as device_count
    FROM clients c
    LEFT JOIN plans p ON c.plan_id = p.id
    LEFT JOIN users u ON c.user_id = u.id
    WHERE 1=1
    """
    params = []
    if search:
        s = "%" + search.strip().lower() + "%"
        query += " AND (LOWER(c.name) LIKE ? OR LOWER(c.email) LIKE ? OR LOWER(u.username) LIKE ?)"
        params.extend([s, s, s])
    query += " ORDER BY c.id DESC;"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_client(client_id: int) -> Optional[Dict[str, Any]]:
    refresh_expired_clients()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.*, p.name as plan_name, p.price as plan_price, p.max_devices as max_devices,
           p.duration_days as duration_days, u.username as username
    FROM clients c
    LEFT JOIN plans p ON c.plan_id = p.id
    LEFT JOIN users u ON c.user_id = u.id
    WHERE c.id = ? LIMIT 1;
    """, (client_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_client_by_user_id(user_id: int) -> Optional[Dict[str, Any]]:
    refresh_expired_clients()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.*, p.name as plan_name, p.price as plan_price, p.max_devices as max_devices,
           p.duration_days as duration_days, u.username as username
    FROM clients c
    LEFT JOIN plans p ON c.plan_id = p.id
    LEFT JOIN users u ON c.user_id = u.id
    WHERE c.user_id = ? LIMIT 1;
    """, (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_client(name: str, email: str, phone: str, plan_id: int, username: str, password: str, notes: str = "") -> Optional[int]:
    conn = get_db()
    cursor = conn.cursor()
    now_dt = datetime.now()
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("SELECT duration_days FROM plans WHERE id = ?;", (plan_id,))
    plan_row = cursor.fetchone()
    days = plan_row["duration_days"] if plan_row else 30
    expires_at = (now_dt + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 'client', 1, ?);",
            (username.strip(), email.strip(), hash_password(password), now)
        )
        user_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO clients (user_id, plan_id, name, email, phone, status, expires_at, notes, created_at) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?);",
            (user_id, plan_id, name.strip(), email.strip(), phone.strip(), expires_at, notes.strip(), now)
        )
        client_id = cursor.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        client_id = None
    finally:
        conn.close()
    return client_id

def update_client_status(client_id: int, status: str) -> bool:
    if status not in ["ACTIVE", "SUSPENDED", "EXPIRED"]:
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET status = ? WHERE id = ?;", (status, client_id))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

def renew_client(client_id: int, extra_days: Optional[int] = None) -> Optional[str]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.expires_at, p.duration_days
    FROM clients c
    LEFT JOIN plans p ON c.plan_id = p.id
    WHERE c.id = ?;
    """, (client_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    days = extra_days if extra_days is not None else (row["duration_days"] or 30)
    now_dt = datetime.now()
    try:
        current_exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
        base_dt = current_exp if current_exp > now_dt else now_dt
    except Exception:
        base_dt = now_dt
    new_exp = (base_dt + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE clients SET expires_at = ?, status = 'ACTIVE' WHERE id = ?;", (new_exp, client_id))
    conn.commit()
    conn.close()
    return new_exp

def delete_client(client_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM clients WHERE id = ?;", (client_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False
    user_id = row["user_id"]
    cursor.execute("DELETE FROM clients WHERE id = ?;", (client_id,))
    if user_id:
        cursor.execute("DELETE FROM users WHERE id = ?;", (user_id,))
    conn.commit()
    conn.close()
    return True

def list_devices(client_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    if client_id is not None:
        cursor.execute("SELECT * FROM devices WHERE client_id = ? ORDER BY id DESC;", (client_id,))
    else:
        cursor.execute("""
        SELECT d.*, c.name as client_name, c.status as client_status
        FROM devices d
        JOIN clients c ON d.client_id = c.id
        ORDER BY d.id DESC;
        """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def list_active_vpn_devices() -> List[Dict[str, Any]]:
    """Returns only devices whose parent client is ACTIVE and not expired."""
    refresh_expired_clients()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT d.*, c.name as client_name
    FROM devices d
    JOIN clients c ON d.client_id = c.id
    WHERE d.is_active = 1 AND c.status = 'ACTIVE'
    ORDER BY d.id ASC;
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_device(device_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE id = ?;", (device_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_next_vpn_ip() -> str:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT vpn_ip FROM devices;")
    used = {row["vpn_ip"] for row in cursor.fetchall()}
    conn.close()
    # Start at 10.8.0.2 (10.8.0.1 is the server)
    for third in range(0, 255):
        start_fourth = 2 if third == 0 else 1
        for fourth in range(start_fourth, 255):
            candidate = f"10.8.{third}.{fourth}"
            if candidate not in used:
                return candidate
    raise RuntimeError("No available VPN IP addresses in 10.8.0.0/16")

def add_device(client_id: int, name: str, vpn_ip: str, wg_public_key: str, wg_private_key: str) -> int:
    conn = get_db()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO devices (client_id, name, vpn_ip, wg_public_key, wg_private_key, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?);",
        (client_id, name.strip(), vpn_ip, wg_public_key, wg_private_key, now)
    )
    device_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return device_id

def delete_device(device_id: int) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = ?;", (device_id,))
    ok = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return ok

# ==================== BLOCKED DOMAINS ====================

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

def list_categories_summary() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT category,
           COUNT(*) as total,
           SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as active_count
    FROM blocked_domains
    GROUP BY category
    ORDER BY total DESC;
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def toggle_category(category: str, enable: int) -> int:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocked_domains SET enabled = ? WHERE category = ?;", (1 if enable else 0, category))
    updated = cursor.rowcount
    conn.commit()
    conn.close()
    return updated

def get_blocked_domain_info(domain: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    clean_domain = domain.strip().lower()
    cursor.execute("SELECT * FROM blocked_domains WHERE domain = ? AND enabled = 1 LIMIT 1;", (clean_domain,))
    row = cursor.fetchone()
    if not row:
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

# ==================== QUERY LOGS & STATS ====================

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
    refresh_expired_clients()
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

    cursor.execute("SELECT COUNT(*) FROM clients WHERE status = 'ACTIVE';")
    active_subscribers = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COALESCE(SUM(p.price), 0)
    FROM clients c
    JOIN plans p ON c.plan_id = p.id
    WHERE c.status = 'ACTIVE';
    """)
    mrr = round(float(cursor.fetchone()[0] or 0.0), 2)

    cursor.execute("SELECT COUNT(*) FROM devices WHERE is_active = 1;")
    total_devices = cursor.fetchone()[0]

    block_rate = round((total_blocked / total_queries * 100), 1) if total_queries > 0 else 0.0

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
        "active_subscribers": active_subscribers,
        "mrr": mrr,
        "total_devices": total_devices,
        "block_rate": block_rate,
        "chart_data": chart_data,
        "top_blocked": top_blocked
    }

# ==================== UNBLOCK REQUESTS ====================

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

# ==================== SETTINGS ====================

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
