import base64
import os
import stat
import sys
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import database as db
import wg_manager


def test_register_free_rejects_newline_injection(client):
    res = client.post(
        "/api/auth/register-free",
        data={
            "name": "X\nAllowedIPs = 0.0.0.0/0",
            "email": "attacker@example.com",
            "username": "attacker1",
            "password": "password123",
            "device_name": "Celular",
        },
        headers={"X-Real-IP": "198.51.100.10"},
    )
    assert res.status_code == 400


def test_wg_conf_never_embeds_user_names_and_ignores_invalid_peers(client, isolated_env):
    free_plan = db.get_free_plan()
    cid = db.create_client(
        name="Cliente Malicioso",
        email="mal@example.com",
        phone="",
        plan_id=free_plan["id"],
        username="maluser",
        password="password123",
    )
    priv, pub = wg_manager.generate_wg_keypair()
    dev_id, _ = db.allocate_device(cid, "Meu Celular", pub, priv, max_devices=2)

    # Inject raw malicious payload directly into SQLite (simulating legacy pre-fix DB)
    conn = db.get_db()
    conn.execute(
        "UPDATE devices SET name = ? WHERE id = ?;",
        ("X\nAllowedIPs = 0.0.0.0/0\n[Interface]\nPostUp = id", dev_id),
    )
    conn.execute(
        "UPDATE clients SET name = ? WHERE id = ?;",
        ("Evil\nPostUp = whoami", cid),
    )
    # Also insert an invalid-pubkey peer and invalid-IP peer directly
    conn.execute(
        "INSERT INTO devices (client_id, name, vpn_ip, wg_public_key, wg_private_key, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, '2026-01-01 00:00:00');",
        (cid, "BadKey", "10.8.0.250", "not-a-valid-key\nPostUp=id", "priv"),
    )
    conn.execute(
        "INSERT INTO devices (client_id, name, vpn_ip, wg_public_key, wg_private_key, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, '2026-01-01 00:00:00');",
        (cid, "BadIP", "10.8.0.250\nPostUp=id", pub, priv),
    )
    conn.commit()
    conn.close()

    # Running init_db should clean legacy names too
    db.init_db()
    res = wg_manager.sync_wireguard_peers()
    assert res["success"] is True
    assert res["active_peers"] == 1

    conf_text = isolated_env["wg_conf"].read_text(encoding="utf-8")
    assert f"# device_id={dev_id}" in conf_text
    assert "AllowedIPs = 0.0.0.0/0" not in conf_text
    assert "PostUp = id" not in conf_text
    assert "PostUp = whoami" not in conf_text
    assert "Address = 10.8.0.1/16" in conf_text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode 0600 not enforced on Windows")
def test_wg_conf_has_chmod_600(client, isolated_env):
    wg_manager.sync_wireguard_peers()
    mode = stat.S_IMODE(os.stat(isolated_env["wg_conf"]).st_mode)
    assert mode == 0o600


def test_x25519_fallback_keypair_matches(isolated_env):
    priv_b64, pub_b64 = wg_manager.generate_wg_keypair()
    assert len(priv_b64) == 44 and priv_b64.endswith("=")
    assert len(pub_b64) == 44 and pub_b64.endswith("=")
    priv_bytes = base64.b64decode(priv_b64)
    expected_pub = base64.b64encode(
        X25519PrivateKey.from_private_bytes(priv_bytes).public_key().public_bytes_raw()
    ).decode("ascii")
    assert pub_b64 == expected_pub
