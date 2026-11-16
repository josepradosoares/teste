import os
import re
import ipaddress
import tempfile
import subprocess
import threading
import logging
from typing import List, Dict, Any
from database import list_blocked_domains, get_settings, get_enabled_blocked_domains_set, log_queries_batch
from validators import normalize_domain

logger = logging.getLogger("netshield.dns")

DNSMASQ_BLOCK_CONF = os.environ.get("NETSHIELD_DNSMASQ_CONF", "/etc/dnsmasq.d/netshield_blocked.conf")
DNSMASQ_FREE_BLOCK_CONF = os.environ.get("NETSHIELD_DNSMASQ_FREE_CONF", "/etc/netshield/dnsmasq-free.d/netshield_free_blocked.conf")
DNSMASQ_UPSTREAM_CONF = os.environ.get("NETSHIELD_DNSMASQ_UPSTREAM_CONF", "/etc/netshield/dnsmasq-upstream.conf")
DNSMASQ_LOG_PATH = os.environ.get("NETSHIELD_LOG_PATH", "/var/log/dnsmasq.log")

_dns_sync_lock = threading.Lock()
MAX_LOG_READ_BYTES = 2 * 1024 * 1024  # 2 MB per parse call

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

# Bloqueio silencioso de anúncios do YouTube (somente Plano Pago / Completo).
# Respondidos com endereço nulo (0.0.0.0 / ::) independentemente do block_mode,
# para nunca exibir tela de bloqueio nem aviso. dnsmasq aplica a regra também a
# todos os subdomínios. NÃO incluir hosts necessários para a reprodução
# (youtube.com, s.youtube.com, youtubei.googleapis.com, googlevideo.com, ytimg.com,
# jnn-pa.googleapis.com, imasdk.googleapis.com...), pois quebrariam vídeos/apps.
YOUTUBE_AD_DOMAINS = [
    "doubleclick.net",            # googleads.g / pubads.g / securepubads.g / ad / static
    "googleadservices.com",
    "googlesyndication.com",      # pagead2 / tpc
    "googletagservices.com",
    "adservice.google.com",
    "adservice.google.com.br",
    "ads.youtube.com",
]


def _youtube_adblock_enabled(settings: Dict[str, str]) -> bool:
    return str(settings.get("youtube_adblock", "1")).strip() == "1"


def _atomic_write_text(target_path: str, content: str):
    abs_path = os.path.abspath(target_path)
    conf_dir = os.path.dirname(abs_path)
    if conf_dir and not os.path.exists(conf_dir):
        os.makedirs(conf_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".ns_", suffix=".tmp", dir=conf_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, abs_path)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        raise


def _write_conf_with_fallback(target_path: str, fallback_path: str, content: str) -> bool:
    try:
        _atomic_write_text(target_path, content)
        return True
    except (PermissionError, FileNotFoundError, OSError):
        try:
            _atomic_write_text(fallback_path, content)
            logger.info(f"Fallback written to {fallback_path}")
            return True
        except Exception as e:
            logger.error(f"Error writing fallback blocklist {fallback_path}: {e}")
            return False
    except Exception as e:
        logger.error(f"Error writing blocklist {target_path}: {e}")
        return False


def _build_upstream_conf(upstream_raw: str) -> str:
    valid_ips: List[str] = []
    for token in re.split(r"[\s,;]+", (upstream_raw or "").strip()):
        if not token:
            continue
        try:
            ip_obj = ipaddress.ip_address(token)
            if str(ip_obj) not in valid_ips:
                valid_ips.append(str(ip_obj))
        except ValueError:
            logger.warning(f"Ignoring invalid upstream DNS IP: {token!r}")
    if not valid_ips:
        valid_ips = ["1.1.1.1", "8.8.8.8"]
    lines = ["# NetShield DNS - Upstream DNS servers (auto-generated)"]
    lines.extend(f"server={ip}" for ip in valid_ips)
    return "\n".join(lines) + "\n"


def sync_dnsmasq_blocklist() -> Dict[str, Any]:
    """
    Reads active blocked domains from SQLite and generates:
      1) Paid/Full dnsmasq blocklist (all enabled rules)
      2) Free Family & Christian dnsmasq blocklist (free_included == 1 + SafeSearch)
      3) Upstream DNS servers config (DNSMASQ_UPSTREAM_CONF)
    Then reloads both dnsmasq services so changes take effect immediately.
    """
    with _dns_sync_lock:
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
        paid_domains = set()
        youtube_adblock = _youtube_adblock_enabled(settings)
        youtube_ad_set = set(YOUTUBE_AD_DOMAINS) if youtube_adblock else set()

        for item in blocked_domains:
            if item.get("enabled", 1) == 1:
                try:
                    dom = normalize_domain(item.get("domain", ""))
                except ValueError:
                    logger.warning(f"Skipping invalid blocked domain in DB: {item.get('domain')!r}")
                    continue

                # Se o bloqueio de anúncios do YouTube estiver ativo, domínios de anúncios
                # de vídeo não devem receber o IP do sinkhole (tela de bloqueio), e sim 0.0.0.0/::
                if dom not in youtube_ad_set:
                    rule = f"address=/{dom}/{target_ip}"
                    paid_lines.append(rule)
                    paid_domains.add(dom)
                    active_count += 1

                if item.get("free_included", 0) == 1:
                    free_lines.append(f"address=/{dom}/{target_ip}")
                    free_count += 1

        if youtube_adblock:
            paid_lines.append("")
            paid_lines.append("# Bloqueio silencioso de anúncios do YouTube (Plano Pago) - sem tela de bloqueio")
            for dom in YOUTUBE_AD_DOMAINS:
                paid_lines.append(f"address=/{dom}/0.0.0.0")
                paid_lines.append(f"address=/{dom}/::")
                if dom not in paid_domains:
                    active_count += 1

        paid_content = "\n".join(paid_lines) + "\n"
        free_content = "\n".join(free_lines) + "\n"
        upstream_content = _build_upstream_conf(settings.get("upstream_dns", "1.1.1.1, 8.8.8.8"))

        write_paid = _write_conf_with_fallback(DNSMASQ_BLOCK_CONF, "/tmp/netshield_blocked.conf", paid_content)
        write_free = _write_conf_with_fallback(DNSMASQ_FREE_BLOCK_CONF, "/tmp/netshield_free_blocked.conf", free_content)
        write_upstream = _write_conf_with_fallback(DNSMASQ_UPSTREAM_CONF, "/tmp/netshield_upstream.conf", upstream_content)

        # Reload both dnsmasq instances
        reload_status = reload_dnsmasq_service()

        return {
            "success": write_paid and write_free and write_upstream,
            "active_rules": active_count,
            "free_rules": free_count,
            "sinkhole_ip": target_ip,
            "block_mode": block_mode,
            "youtube_adblock": youtube_adblock,
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

    with _log_parse_lock:
        try:
            current_size = os.path.getsize(DNSMASQ_LOG_PATH)
            if current_size < _last_log_position:
                _last_log_position = 0 # Log was rotated

            blocked_set = get_enabled_blocked_domains_set()
            batch = []

            with open(DNSMASQ_LOG_PATH, "rb") as f:
                if _last_log_position == 0 and current_size > 5000:
                    f.seek(current_size - 4000) # Start near the end on first run
                else:
                    f.seek(_last_log_position)

                bytes_read = 0
                while bytes_read < MAX_LOG_READ_BYTES:
                    raw_line = f.readline()
                    if not raw_line:
                        break
                    bytes_read += len(raw_line)
                    line = raw_line.decode("utf-8", errors="ignore")
                    m = query_pattern.search(line)
                    if m:
                        qtype = m.group("type")
                        domain = m.group("domain").lower()
                        ip = m.group("ip")
                        if domain.endswith("."):
                            domain = domain[:-1]
                        alt = domain[4:] if domain.startswith("www.") else f"www.{domain}"
                        status = "BLOCKED" if (domain in blocked_set or alt in blocked_set) else "ALLOWED"
                        batch.append((ip, domain, qtype, status))

                _last_log_position = f.tell()

            if batch:
                log_queries_batch(batch)
        except Exception as e:
            logger.error(f"Error parsing log file: {e}")
