import os
import re
import subprocess
import threading
import logging
from typing import List, Dict, Any
from database import list_blocked_domains, get_settings, log_query, increment_hits

logger = logging.getLogger("netshield.dns")

DNSMASQ_BLOCK_CONF = os.environ.get("NETSHIELD_DNSMASQ_CONF", "/etc/dnsmasq.d/netshield_blocked.conf")
DNSMASQ_FREE_BLOCK_CONF = os.environ.get("NETSHIELD_DNSMASQ_FREE_CONF", "/etc/dnsmasq.d/netshield_free_blocked.conf")
DNSMASQ_LOG_PATH = os.environ.get("NETSHIELD_LOG_PATH", "/var/log/dnsmasq.log")

SAFESEARCH_RULES = [
    "# SafeSearch & YouTube Restricted Mode (Plano Free Família & Cristão)",
    "address=/www.google.com/216.239.38.120",
    "address=/google.com/216.239.38.120",
    "address=/www.google.com.br/216.239.38.120",
    "address=/google.com.br/216.239.38.120",
    "address=/www.bing.com/204.79.197.220",
    "address=/www.youtube.com/216.239.38.119",
    "address=/m.youtube.com/216.239.38.119",
    "address=/youtubei.googleapis.com/216.239.38.119",
    "address=/www.youtube-nocookie.com/216.239.38.119",
    ""
]

def _write_conf_with_fallback(target_path: str, fallback_path: str, content: str) -> bool:
    try:
        conf_dir = os.path.dirname(target_path)
        if conf_dir and not os.path.exists(conf_dir):
            os.makedirs(conf_dir, exist_ok=True)
        with open(target_path, "w") as f:
            f.write(content)
        return True
    except (PermissionError, FileNotFoundError, OSError):
        try:
            with open(fallback_path, "w") as f:
                f.write(content)
            logger.info(f"Fallback written to {fallback_path}")
            return True
        except Exception as e:
            logger.error(f"Error writing fallback blocklist {fallback_path}: {e}")
            return False
    except Exception as e:
        logger.error(f"Error writing blocklist {target_path}: {e}")
        return False

def sync_dnsmasq_blocklist() -> Dict[str, Any]:
    """
    Reads active blocked domains from SQLite and generates both:
      1) Paid/Full dnsmasq blocklist (all enabled rules)
      2) Free Family & Christian dnsmasq blocklist (free_included == 1 + SafeSearch)
    Then reloads both dnsmasq services so changes take effect immediately.
    """
    settings = get_settings()
    server_ip = settings.get("server_ip", "127.0.0.1")
    block_mode = settings.get("block_mode", "sinkhole")
    target_ip = "0.0.0.0" if block_mode == "null" else server_ip
    blocked_domains = list_blocked_domains()

    paid_lines = [
        "# ====================================================",
        "# NetShield DNS - Automated Blocklist (Planos Pagos / Completo)",
        f"# Block Mode: {block_mode} | Target IP: {target_ip}",
        "# Do not edit manually - managed by NetShield Web Panel",
        "# ====================================================",
        ""
    ]

    free_lines = [
        "# ====================================================",
        "# NetShield DNS - Automated Blocklist (Plano Free Família & Cristão)",
        f"# Block Mode: {block_mode} | Target IP: {target_ip}",
        "# Do not edit manually - managed by NetShield Web Panel",
        "# ====================================================",
        ""
    ] + SAFESEARCH_RULES

    active_count = 0
    free_count = 0
    for item in blocked_domains:
        if item.get("enabled", 1) == 1:
            dom = item["domain"].strip().lower()
            if dom:
                rule = f"address=/{dom}/{target_ip}"
                paid_lines.append(rule)
                active_count += 1
                if item.get("free_included", 0) == 1:
                    free_lines.append(rule)
                    free_count += 1

    paid_content = "\n".join(paid_lines) + "\n"
    free_content = "\n".join(free_lines) + "\n"

    write_paid = _write_conf_with_fallback(DNSMASQ_BLOCK_CONF, "/tmp/netshield_blocked.conf", paid_content)
    write_free = _write_conf_with_fallback(DNSMASQ_FREE_BLOCK_CONF, "/tmp/netshield_free_blocked.conf", free_content)

    # Reload both dnsmasq instances
    reload_status = reload_dnsmasq_service()

    return {
        "success": write_paid and write_free,
        "active_rules": active_count,
        "free_rules": free_count,
        "sinkhole_ip": target_ip,
        "block_mode": block_mode,
        "dnsmasq_reloaded": reload_status
    }

def reload_dnsmasq_service() -> bool:
    """Attempts to signal both dnsmasq (paid) and netshield-dns-free (free) to reload configs."""
    paid_ok = False
    for cmd in [["systemctl", "reload", "dnsmasq"], ["systemctl", "restart", "dnsmasq"], ["killall", "-HUP", "dnsmasq"]]:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            if res.returncode == 0:
                paid_ok = True
                break
        except Exception:
            continue

    for cmd in [["systemctl", "reload", "netshield-dns-free"], ["systemctl", "restart", "netshield-dns-free"]]:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            if res.returncode == 0:
                break
        except Exception:
            continue

    return paid_ok

_last_log_position = 0
_log_parse_lock = threading.Lock()

def parse_dnsmasq_log_stream():
    """
    Incrementally reads new queries from dnsmasq log file without repeating old lines.
    """
    global _last_log_position
    if not os.path.exists(DNSMASQ_LOG_PATH):
        return

    query_pattern = re.compile(r"query\[(?P<type>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)")
    from database import get_blocked_domain_info

    with _log_parse_lock:
        try:
            current_size = os.path.getsize(DNSMASQ_LOG_PATH)
            if current_size < _last_log_position:
                _last_log_position = 0 # Log was rotated

            with open(DNSMASQ_LOG_PATH, "r", errors="ignore") as f:
                if _last_log_position == 0 and current_size > 5000:
                    f.seek(current_size - 4000) # Start near the end on first run
                else:
                    f.seek(_last_log_position)

                lines = f.readlines()
                _last_log_position = f.tell()

                for line in lines:
                    m = query_pattern.search(line)
                    if m:
                        qtype = m.group("type")
                        domain = m.group("domain").lower()
                        ip = m.group("ip")
                        if domain.endswith("."):
                            domain = domain[:-1]
                        is_blocked = get_blocked_domain_info(domain) is not None
                        status = "BLOCKED" if is_blocked else "ALLOWED"
                        log_query(client_ip=ip, domain=domain, status=status, query_type=qtype)
        except Exception as e:
            logger.error(f"Error parsing log file: {e}")
