import os
import io
import base64
import ipaddress
import tempfile
import threading
import subprocess
import logging
from typing import Tuple, Dict, Any, Optional
import qrcode
import qrcode.image.svg
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import database as db

logger = logging.getLogger("netshield.wg")

WG_CONF_PATH = os.environ.get("NETSHIELD_WG_CONF", "/etc/wireguard/wg0.conf")
WG_SERVER_PRIV_PATH = os.environ.get("NETSHIELD_WG_SERVER_PRIV", "/etc/wireguard/server_private.key")
WG_SERVER_PUB_PATH = os.environ.get("NETSHIELD_WG_SERVER_PUB", "/etc/wireguard/server_public.key")

_wg_sync_lock = threading.RLock()


def _is_valid_wg_pubkey(pub: str) -> bool:
    if not isinstance(pub, str):
        return False
    pub = pub.strip()
    if len(pub) != 44 or not pub.endswith("="):
        return False
    try:
        raw = base64.b64decode(pub, validate=True)
        return len(raw) == 32
    except Exception:
        return False


def _atomic_write_private_file(target_path: str, content: str):
    abs_path = os.path.abspath(target_path)
    target_dir = os.path.dirname(abs_path)
    if target_dir:
        os.makedirs(target_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".wg_", suffix=".tmp", dir=target_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except Exception:
            pass
        os.replace(tmp_path, abs_path)
        try:
            os.chmod(abs_path, 0o600)
        except Exception:
            pass
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        raise


def generate_wg_keypair() -> Tuple[str, str]:
    """Generates a WireGuard private and public key pair using wg CLI, with X25519 fallback."""
    try:
        priv = subprocess.check_output(["wg", "genkey"], stderr=subprocess.DEVNULL, timeout=3).decode().strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode(), stderr=subprocess.DEVNULL, timeout=3).decode().strip()
        return priv, pub
    except Exception:
        priv_obj = X25519PrivateKey.generate()
        priv = base64.b64encode(priv_obj.private_bytes_raw()).decode("ascii")
        pub = base64.b64encode(priv_obj.public_key().public_bytes_raw()).decode("ascii")
        return priv, pub

def get_server_public_key() -> str:
    """Retrieves the WireGuard server public key from disk or settings."""
    if os.path.exists(WG_SERVER_PUB_PATH):
        try:
            with open(WG_SERVER_PUB_PATH, "r") as f:
                pub = f.read().strip()
                if pub:
                    db.update_setting("wg_server_pubkey", pub)
                    return pub
        except Exception:
            pass
    settings = db.get_settings()
    pub = settings.get("wg_server_pubkey", "").strip()
    if pub:
        return pub
    return "CONFIGURAR_CHAVE_PUBLICA_DO_SERVIDOR"

def get_server_private_key() -> str:
    if os.path.exists(WG_SERVER_PRIV_PATH):
        try:
            with open(WG_SERVER_PRIV_PATH, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""

def vpn_ipv4_to_ipv6(vpn_ip: str) -> str:
    """Maps 10.8.<third>.<fourth> deterministically to a ULA IPv6 address under fd10:8::/64."""
    parts = (vpn_ip or "").strip().split(".")
    if len(parts) == 4 and parts[0] == "10" and parts[1] == "8":
        try:
            third = int(parts[2])
            fourth = int(parts[3])
            if 0 <= third <= 255 and 0 <= fourth <= 255:
                return f"fd10:8::{fourth:x}" if third == 0 else f"fd10:8::{third:x}:{fourth:x}"
        except ValueError:
            pass
    return "fd10:8::2"


def resolve_effective_tunnel_mode(device: Dict[str, Any], settings: Optional[Dict[str, str]] = None) -> str:
    """
    Determines the effective WireGuard tunnel mode for a device:
      - Free plan (plan_price <= 0): always 'dns_only' (Split-Tunnel DNS)
      - Paid plan (plan_price > 0): 'full' (Encrypted VPN + VPS IP) by default,
        or device's explicit choice ('full' / 'dns_only') when set.
    """
    plan_price = float(device.get("plan_price") or 0)
    if plan_price <= 0:
        return "dns_only"

    dev_mode = (device.get("tunnel_mode") or "auto").strip().lower()
    if dev_mode in ("full", "dns_only"):
        return dev_mode
    return "full"


def build_client_config(device: Dict[str, Any]) -> str:
    """Builds the dual-stack (IPv4 + IPv6) .conf file content for a client device."""
    settings = db.get_settings()
    server_ip = settings.get("server_ip", "").strip()
    wg_port = settings.get("wg_endpoint_port", "51820").strip() or "51820"
    effective_mode = resolve_effective_tunnel_mode(device, settings)
    server_pubkey = get_server_public_key()
    vpn_ipv6 = vpn_ipv4_to_ipv6(device["vpn_ip"])

    allowed_ips = "10.8.0.1/32, fd10:8::1/128" if effective_mode == "dns_only" else "0.0.0.0/0, ::/0"

    return (
        f"[Interface]\n"
        f"PrivateKey = {device['wg_private_key']}\n"
        f"Address = {device['vpn_ip']}/32, {vpn_ipv6}/128\n"
        f"DNS = 10.8.0.1, fd10:8::1\n"
        f"MTU = 1380\n\n"
        f"[Peer]\n"
        f"PublicKey = {server_pubkey}\n"
        f"Endpoint = {server_ip}:{wg_port}\n"
        f"AllowedIPs = {allowed_ips}\n"
        f"PersistentKeepalive = 25\n"
    )

def generate_qr_svg(config_text: str) -> str:
    """Generates a crisp inline SVG QR code from WireGuard config text."""
    factory = qrcode.image.svg.SvgPathImage
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
        image_factory=factory
    )
    qr.add_data(config_text)
    qr.make(fit=True)
    img = qr.make_image(attrib={"class": "wg-qr-svg"})
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")

def sync_wireguard_peers() -> Dict[str, Any]:
    """
    Rewrites /etc/wireguard/wg0.conf with the [Interface] block and all ACTIVE client devices,
    then applies changes live using `wg syncconf` without dropping active tunnels.
    """
    with _wg_sync_lock:
        active_devices = db.list_active_vpn_devices()
        priv_key = get_server_private_key()
        settings = db.get_settings()
        wg_port = settings.get("wg_endpoint_port", "51820").strip() or "51820"

        if not priv_key:
            sync_router_dns_nat()
            return {"success": False, "synced": False, "reason": "WireGuard server key not present on this host", "active_peers": len(active_devices)}

        # Detect WAN interface
        wan_iface = "ens3"
        try:
            out = subprocess.check_output(["sh", "-c", "ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $5}' | head -n 1"], timeout=2).decode().strip()
            if out:
                wan_iface = out
        except Exception:
            pass

        lines = [
            "[Interface]",
            "Address = 10.8.0.1/16, fd10:8::1/64",
            f"ListenPort = {wg_port}",
            "MTU = 1380",
            f"PrivateKey = {priv_key}",
            (
                f"PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true; "
                f"sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true; "
                f"iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i wg0 -j ACCEPT; "
                f"iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o wg0 -j ACCEPT; "
                f"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; "
                f"iptables -t nat -C POSTROUTING -s 10.8.0.0/16 -o {wan_iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o {wan_iface} -j MASQUERADE; "
                f"ip6tables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -i wg0 -j ACCEPT 2>/dev/null || true; "
                f"ip6tables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -o wg0 -j ACCEPT 2>/dev/null || true; "
                f"ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; "
                f"ip6tables -t nat -C POSTROUTING -s fd10:8::/64 -o {wan_iface} -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s fd10:8::/64 -o {wan_iface} -j MASQUERADE 2>/dev/null || true"
            ),
            (
                f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; "
                f"iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true; "
                f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; "
                f"iptables -t nat -D POSTROUTING -s 10.8.0.0/16 -o {wan_iface} -j MASQUERADE 2>/dev/null || true; "
                f"ip6tables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; "
                f"ip6tables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true; "
                f"ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true; "
                f"ip6tables -t nat -D POSTROUTING -s fd10:8::/64 -o {wan_iface} -j MASQUERADE 2>/dev/null || true"
            ),
            ""
        ]

        valid_devices = []
        for dev in active_devices:
            pub = (dev.get("wg_public_key") or "").strip()
            raw_ip = (dev.get("vpn_ip") or "").strip()
            try:
                ip_obj = ipaddress.IPv4Address(raw_ip)
            except ValueError:
                logger.warning(f"Skipping WireGuard peer device_id={dev.get('id')}: invalid vpn_ip={raw_ip!r}")
                continue
            if not _is_valid_wg_pubkey(pub):
                logger.warning(f"Skipping WireGuard peer device_id={dev.get('id')}: invalid public key")
                continue

            vpn_ip_str = str(ip_obj)
            vpn_ipv6 = vpn_ipv4_to_ipv6(vpn_ip_str)
            lines.extend([
                "[Peer]",
                f"# device_id={int(dev['id'])}",
                f"PublicKey = {pub}",
                f"AllowedIPs = {vpn_ip_str}/32, {vpn_ipv6}/128",
                ""
            ])
            valid_devices.append(dev)

        content = "\n".join(lines)
        try:
            _atomic_write_private_file(WG_CONF_PATH, content)
            # Live reload without dropping existing connections
            subprocess.run(
                ["bash", "-c", f"wg syncconf wg0 <(wg-quick strip {WG_CONF_PATH})"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            _ensure_wg_forwarding(wan_iface)
            _sync_free_dns_nat(valid_devices)
            sync_router_dns_nat()
            return {"success": True, "synced": True, "active_peers": len(valid_devices)}
        except Exception as e:
            logger.warning(f"Could not sync WireGuard config: {e}")
            return {"success": False, "synced": False, "reason": str(e), "active_peers": len(valid_devices)}


def _ensure_wg_forwarding(wan_iface: str):
    """Ensures IPv4/IPv6 forwarding, /16 route, FORWARD (above Oracle Cloud REJECT), TCPMSS clamping, and MASQUERADE are active."""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run(["ip", "route", "replace", "10.8.0.0/16", "dev", "wg0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        rules = [
            (["iptables", "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "1", "-i", "wg0", "-j", "ACCEPT"]),
            (["iptables", "-C", "FORWARD", "-o", "wg0", "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "1", "-o", "wg0", "-j", "ACCEPT"]),
            (["iptables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
            (["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.8.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"], ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"]),
            (["ip6tables", "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"], ["ip6tables", "-I", "FORWARD", "1", "-i", "wg0", "-j", "ACCEPT"]),
            (["ip6tables", "-C", "FORWARD", "-o", "wg0", "-j", "ACCEPT"], ["ip6tables", "-I", "FORWARD", "1", "-o", "wg0", "-j", "ACCEPT"]),
            (["ip6tables", "-t", "mangle", "-C", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"], ["ip6tables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
            (["ip6tables", "-t", "nat", "-C", "POSTROUTING", "-s", "fd10:8::/64", "-o", wan_iface, "-j", "MASQUERADE"], ["ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", "fd10:8::/64", "-o", wan_iface, "-j", "MASQUERADE"]),
        ]
        for check_cmd, add_cmd in rules:
            if subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode != 0:
                subprocess.run(add_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception as e:
        logger.warning(f"Could not ensure WG forwarding rules: {e}")


def _sync_free_dns_nat(active_devices):
    """
    Redirects DNS (UDP/TCP 53) from Free-tier VPN IPs (IPv4 & IPv6, plan_price <= 0) to port 5354
    where netshield-dns-free runs the Christian & Family Free rules + SafeSearch.
    """
    try:
        # IPv4 NAT chain
        subprocess.run(["iptables", "-t", "nat", "-N", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run(["iptables", "-t", "nat", "-F", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)

        for proto in ("udp", "tcp"):
            chk = subprocess.run(
                ["iptables", "-t", "nat", "-C", "PREROUTING", "-i", "wg0", "-d", "10.8.0.1", "-p", proto, "--dport", "53", "-j", "NETSHIELD_DNS_FREE"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
            if chk.returncode != 0:
                subprocess.run(
                    ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", "wg0", "-d", "10.8.0.1", "-p", proto, "--dport", "53", "-j", "NETSHIELD_DNS_FREE"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )

        # IPv6 NAT chain (best effort)
        subprocess.run(["ip6tables", "-t", "nat", "-N", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run(["ip6tables", "-t", "nat", "-F", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        for proto in ("udp", "tcp"):
            chk6 = subprocess.run(
                ["ip6tables", "-t", "nat", "-C", "PREROUTING", "-i", "wg0", "-d", "fd10:8::1", "-p", proto, "--dport", "53", "-j", "NETSHIELD_DNS_FREE"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
            )
            if chk6.returncode != 0:
                subprocess.run(
                    ["ip6tables", "-t", "nat", "-I", "PREROUTING", "1", "-i", "wg0", "-d", "fd10:8::1", "-p", proto, "--dport", "53", "-j", "NETSHIELD_DNS_FREE"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )

        # Add REDIRECT rules for each Free-tier device IPv4 & IPv6
        for dev in active_devices:
            if float(dev.get("plan_price") or 0) <= 0:
                vpn_ip = dev["vpn_ip"]
                vpn_ipv6 = vpn_ipv4_to_ipv6(vpn_ip)
                for proto in ("udp", "tcp"):
                    subprocess.run(
                        ["iptables", "-t", "nat", "-A", "NETSHIELD_DNS_FREE", "-s", f"{vpn_ip}/32", "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                    )
                    subprocess.run(
                        ["ip6tables", "-t", "nat", "-A", "NETSHIELD_DNS_FREE", "-s", f"{vpn_ipv6}/128", "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                    )
    except Exception as e:
        logger.warning(f"Could not sync Free DNS NAT rules: {e}")


def sync_router_dns_nat() -> Dict[str, Any]:
    """
    Routes external router DNS (UDP/TCP 53, non-wg0) by subscriber plan:
      - Registered ACTIVE paid-plan router IPs -> RETURN (served by dnsmasq on port 53)
      - All other external IPs (Free tier or unregistered) -> REDIRECT to port 5354 (dnsmasq-free)
    """
    with _wg_sync_lock:
        paid_ips = db.list_active_paid_router_ips()
        try:
            subprocess.run(["iptables", "-t", "nat", "-N", "NETSHIELD_ROUTER_DNS"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            subprocess.run(["iptables", "-t", "nat", "-F", "NETSHIELD_ROUTER_DNS"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)

            for proto in ("udp", "tcp"):
                chk = subprocess.run(
                    ["iptables", "-t", "nat", "-C", "PREROUTING", "!", "-i", "wg0", "!", "-s", "127.0.0.0/8", "-p", proto, "--dport", "53", "-j", "NETSHIELD_ROUTER_DNS"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )
                if chk.returncode != 0:
                    subprocess.run(
                        ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "!", "-i", "wg0", "!", "-s", "127.0.0.0/8", "-p", proto, "--dport", "53", "-j", "NETSHIELD_ROUTER_DNS"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                    )

            for ip in paid_ips:
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "NETSHIELD_ROUTER_DNS", "-s", f"{ip}/32", "-j", "RETURN"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )

            for proto in ("udp", "tcp"):
                subprocess.run(
                    ["iptables", "-t", "nat", "-A", "NETSHIELD_ROUTER_DNS", "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )

            return {"success": True, "paid_router_ips": len(paid_ips)}
        except Exception as e:
            logger.warning(f"Could not sync Router DNS NAT rules: {e}")
            return {"success": False, "paid_router_ips": len(paid_ips), "reason": str(e)}
