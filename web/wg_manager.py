import os
import io
import base64
import secrets
import subprocess
import logging
from typing import Tuple, Dict, Any
import qrcode
import qrcode.image.svg

import database as db

logger = logging.getLogger("netshield.wg")

WG_CONF_PATH = os.environ.get("NETSHIELD_WG_CONF", "/etc/wireguard/wg0.conf")
WG_SERVER_PRIV_PATH = "/etc/wireguard/server_private.key"
WG_SERVER_PUB_PATH = "/etc/wireguard/server_public.key"

def generate_wg_keypair() -> Tuple[str, str]:
    """Generates a WireGuard private and public key pair using wg CLI, with safe fallback for dev environments."""
    try:
        priv = subprocess.check_output(["wg", "genkey"], stderr=subprocess.DEVNULL, timeout=3).decode().strip()
        pub = subprocess.check_output(["wg", "pubkey"], input=priv.encode(), stderr=subprocess.DEVNULL, timeout=3).decode().strip()
        return priv, pub
    except Exception:
        # Fallback for environments without wireguard-tools installed (e.g. unit testing)
        priv = base64.b64encode(secrets.token_bytes(32)).decode()
        pub = base64.b64encode(secrets.token_bytes(32)).decode()
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

def build_client_config(device: Dict[str, Any]) -> str:
    """Builds the .conf file content for a client device."""
    settings = db.get_settings()
    server_ip = settings.get("server_ip", "152.67.44.54").strip()
    wg_port = settings.get("wg_endpoint_port", "51820").strip() or "51820"
    tunnel_mode = settings.get("wg_tunnel_mode", "full").strip()
    server_pubkey = get_server_public_key()

    allowed_ips = "10.8.0.1/32" if tunnel_mode == "dns_only" else "0.0.0.0/0, ::/0"

    return (
        f"[Interface]\n"
        f"PrivateKey = {device['wg_private_key']}\n"
        f"Address = {device['vpn_ip']}/24\n"
        f"DNS = 10.8.0.1\n"
        f"MTU = 1420\n\n"
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
        "Address = 10.8.0.1/24",
        f"ListenPort = {wg_port}",
        "MTU = 1420",
        f"PrivateKey = {priv_key}",
        f"PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o {wan_iface} -j MASQUERADE; iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t nat -D POSTROUTING -s 10.8.0.0/16 -o {wan_iface} -j MASQUERADE; iptables -t nat -D POSTROUTING -o {wan_iface} -j MASQUERADE",
        ""
    ]

    for dev in active_devices:
        lines.extend([
            f"[Peer]",
            f"# {dev.get('client_name', 'Cliente')} - {dev['name']}",
            f"PublicKey = {dev['wg_public_key']}",
            f"AllowedIPs = {dev['vpn_ip']}/32",
            ""
        ])

    content = "\n".join(lines)
    try:
        with open(WG_CONF_PATH, "w") as f:
            f.write(content)
        # Live reload without dropping existing connections
        subprocess.run(
            ["bash", "-c", f"wg syncconf wg0 <(wg-quick strip {WG_CONF_PATH})"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        _ensure_wg_forwarding(wan_iface)
        _sync_free_dns_nat(active_devices)
        sync_router_dns_nat()
        return {"success": True, "synced": True, "active_peers": len(active_devices)}
    except Exception as e:
        logger.warning(f"Could not sync WireGuard config: {e}")
        return {"success": False, "synced": False, "reason": str(e), "active_peers": len(active_devices)}


def _ensure_wg_forwarding(wan_iface: str):
    """Ensures ip_forward, FORWARD (above Oracle Cloud REJECT), TCPMSS, and MASQUERADE are active."""
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        rules = [
            (["iptables", "-C", "FORWARD", "-i", "wg0", "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "1", "-i", "wg0", "-j", "ACCEPT"]),
            (["iptables", "-C", "FORWARD", "-o", "wg0", "-j", "ACCEPT"], ["iptables", "-I", "FORWARD", "1", "-o", "wg0", "-j", "ACCEPT"]),
            (["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.8.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"], ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.8.0.0/16", "-o", wan_iface, "-j", "MASQUERADE"]),
        ]
        for check_cmd, add_cmd in rules:
            if subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3).returncode != 0:
                subprocess.run(add_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception as e:
        logger.warning(f"Could not ensure WG forwarding rules: {e}")


def _sync_free_dns_nat(active_devices):
    """
    Redirects DNS (UDP/TCP 53) from Free-tier VPN IPs (plan_price == 0) to port 5354
    where netshield-dns-free runs the Christian & Family Free rules + SafeSearch.
    """
    try:
        # Ensure chain exists and is flushed
        subprocess.run(["iptables", "-t", "nat", "-N", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run(["iptables", "-t", "nat", "-F", "NETSHIELD_DNS_FREE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)

        # Ensure PREROUTING jumps to NETSHIELD_DNS_FREE for DNS on wg0
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

        # Add REDIRECT rules for each Free-tier device IP
        for dev in active_devices:
            if float(dev.get("plan_price") or 0) <= 0:
                vpn_ip = dev["vpn_ip"]
                for proto in ("udp", "tcp"):
                    subprocess.run(
                        ["iptables", "-t", "nat", "-A", "NETSHIELD_DNS_FREE", "-s", f"{vpn_ip}/32", "-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
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
