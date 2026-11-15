import os
import re
import subprocess
import logging
from typing import List, Dict, Any
from database import list_blocked_domains, get_settings, log_query, increment_hits

logger = logging.getLogger("netshield.dns")

DNSMASQ_BLOCK_CONF = os.environ.get("NETSHIELD_DNSMASQ_CONF", "/etc/dnsmasq.d/netshield_blocked.conf")
DNSMASQ_LOG_PATH = os.environ.get("NETSHIELD_LOG_PATH", "/var/log/dnsmasq.log")

def sync_dnsmasq_blocklist() -> Dict[str, Any]:
    """
    Reads active blocked domains from SQLite and generates the dnsmasq block configuration.
    Then reloads dnsmasq service so changes take effect immediately.
    """
    settings = get_settings()
    server_ip = settings.get("server_ip", "127.0.0.1")
    blocked_domains = list_blocked_domains()

    lines = [
        "# ====================================================",
        "# NetShield DNS - Automated Blocklist",
        f"# Server Sinkhole IP: {server_ip}",
        "# Do not edit manually - managed by NetShield Web Panel",
        "# ====================================================",
        ""
    ]

    active_count = 0
    for item in blocked_domains:
        if item.get("enabled", 1) == 1:
            dom = item["domain"].strip().lower()
            if dom:
                # Syntax: address=/example.com/192.168.1.100
                lines.append(f"address=/{dom}/{server_ip}")
                active_count += 1

    content = "\n".join(lines) + "\n"

    write_success = False
    try:
        conf_dir = os.path.dirname(DNSMASQ_BLOCK_CONF)
        if conf_dir and not os.path.exists(conf_dir):
            os.makedirs(conf_dir, exist_ok=True)

        with open(DNSMASQ_BLOCK_CONF, "w") as f:
            f.write(content)
        write_success = True
    except (PermissionError, FileNotFoundError, OSError):
        # If running as non-root during testing or directory not writable, fallback to /tmp
        tmp_conf = "/tmp/netshield_blocked.conf"
        try:
            with open(tmp_conf, "w") as f:
                f.write(content)
            logger.info(f"Fallback written to {tmp_conf}")
            write_success = True
        except Exception as e:
            logger.error(f"Error writing fallback blocklist: {e}")
            return {"success": False, "error": str(e), "count": active_count}
    except Exception as e:
        logger.error(f"Error writing blocklist: {e}")
        return {"success": False, "error": str(e), "count": active_count}

    # Reload dnsmasq
    reload_status = reload_dnsmasq_service()

    return {
        "success": write_success,
        "active_rules": active_count,
        "sinkhole_ip": server_ip,
        "dnsmasq_reloaded": reload_status
    }

def reload_dnsmasq_service() -> bool:
    """Attempts to signal dnsmasq to reload its hosts and configs without dropping connections."""
    commands = [
        ["systemctl", "reload", "dnsmasq"],
        ["systemctl", "restart", "dnsmasq"],
        ["killall", "-HUP", "dnsmasq"]
    ]
    for cmd in commands:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            if res.returncode == 0:
                return True
        except Exception:
            continue
    return False

_last_log_position = 0

def parse_dnsmasq_log_stream():
    """
    Incrementally reads new queries from dnsmasq log file without repeating old lines.
    """
    global _last_log_position
    if not os.path.exists(DNSMASQ_LOG_PATH):
        return

    query_pattern = re.compile(r"query\[(?P<type>[^\]]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>\S+)")
    from database import get_blocked_domain_info
    
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
