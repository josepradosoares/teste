import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
if str(WEB_DIR) not in sys.path:
    sys.path.insert(0, str(WEB_DIR))

import database as db
import dns_manager
import wg_manager
import app as web_app


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    db_file = tmp_path / "test_netshield.db"
    wg_conf = tmp_path / "wg0.conf"
    wg_priv = tmp_path / "server_private.key"
    wg_pub = tmp_path / "server_public.key"
    dns_paid = tmp_path / "dnsmasq.d" / "netshield_blocked.conf"
    dns_free = tmp_path / "dnsmasq-free.d" / "netshield_free_blocked.conf"
    dns_upstream = tmp_path / "dnsmasq-upstream.conf"
    dns_log = tmp_path / "dnsmasq.log"

    # Generate valid server keys for tests
    s_priv, s_pub = wg_manager.generate_wg_keypair()
    wg_priv.write_text(s_priv, encoding="utf-8")
    wg_pub.write_text(s_pub, encoding="utf-8")

    monkeypatch.setenv("NETSHIELD_DB_PATH", str(db_file))
    monkeypatch.setenv("NETSHIELD_ADMIN_PASSWORD", "StrongTestPass!123")
    monkeypatch.setattr(db, "DB_PATH", str(db_file))
    monkeypatch.setattr(wg_manager, "WG_CONF_PATH", str(wg_conf))
    monkeypatch.setattr(wg_manager, "WG_SERVER_PRIV_PATH", str(wg_priv))
    monkeypatch.setattr(wg_manager, "WG_SERVER_PUB_PATH", str(wg_pub))
    monkeypatch.setattr(dns_manager, "DNSMASQ_BLOCK_CONF", str(dns_paid))
    monkeypatch.setattr(dns_manager, "DNSMASQ_FREE_BLOCK_CONF", str(dns_free))
    monkeypatch.setattr(dns_manager, "DNSMASQ_UPSTREAM_CONF", str(dns_upstream))
    monkeypatch.setattr(dns_manager, "DNSMASQ_LOG_PATH", str(dns_log))
    monkeypatch.setattr(dns_manager, "_last_log_position", 0)

    # Mock subprocess calls so no real wg/iptables/systemctl runs
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout=b"", stderr=b""))
    monkeypatch.setattr(wg_manager.subprocess, "run", mock_run)
    monkeypatch.setattr(wg_manager.subprocess, "check_output", MagicMock(side_effect=OSError("no wg cli")))
    monkeypatch.setattr(dns_manager.subprocess, "run", mock_run)

    # Reset rate limiters and login lockout state
    web_app.login_ip_rl.reset()
    web_app.register_rl.reset()
    web_app.unblock_rl.reset()
    with web_app._failed_logins_lock:
        web_app._failed_logins.clear()

    return {
        "tmp_path": tmp_path,
        "db_file": db_file,
        "wg_conf": wg_conf,
        "wg_priv": wg_priv,
        "wg_pub": wg_pub,
        "dns_paid": dns_paid,
        "dns_free": dns_free,
        "dns_upstream": dns_upstream,
        "dns_log": dns_log,
    }


@pytest.fixture
def client(isolated_env):
    with TestClient(web_app.app) as c:
        yield c


@pytest.fixture
def admin_client(client):
    res = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "StrongTestPass!123"},
        headers={"X-Real-IP": "10.99.99.1"},
    )
    assert res.status_code == 200
    return client
