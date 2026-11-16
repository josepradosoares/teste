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

    allowed_ips = "10.8.0.1/32" if tunnel_mode == "dns_only" else "0.0.0.0/1, 128.0.0.0/1"

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
        f"PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t nat -A POSTROUTING -o {wan_iface} -j MASQUERADE; iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu; iptables -t nat -D POSTROUTING -o {wan_iface} -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j MASQUERADE",
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
        return {"success": True, "synced": True, "active_peers": len(active_devices)}
    except Exception as e:
        logger.warning(f"Could not sync WireGuard config: {e}")
        return {"success": False, "synced": False, "reason": str(e), "active_peers": len(active_devices)}
