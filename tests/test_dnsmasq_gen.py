import database as db
import dns_manager


def test_malicious_domain_in_db_is_skipped_on_sync(client, isolated_env):
    conn = db.get_db()
    conn.execute(
        "INSERT INTO blocked_domains (domain, reason, category, enabled, free_included, hits, created_at) VALUES (?, ?, ?, 1, 1, 0, '2026-01-01 00:00:00');",
        ("evil.com\ndhcp-script=/bin/sh", "test", "Geral"),
    )
    conn.commit()
    conn.close()

    res = dns_manager.sync_dnsmasq_blocklist()
    assert res["success"] is True

    paid_text = isolated_env["dns_paid"].read_text(encoding="utf-8")
    free_text = isolated_env["dns_free"].read_text(encoding="utf-8")
    assert "dhcp-script" not in paid_text
    assert "dhcp-script" not in free_text
    assert "evil.com" not in paid_text


def test_free_conf_default_path_outside_dnsmasq_d():
    assert "/etc/dnsmasq.d/" not in dns_manager.DNSMASQ_FREE_BLOCK_CONF
    assert "dnsmasq-free.d" in dns_manager.DNSMASQ_FREE_BLOCK_CONF


def test_upstream_conf_validates_ips(admin_client, isolated_env):
    res = admin_client.post(
        "/api/settings",
        data={
            "server_ip": "203.0.113.10",
            "upstream_dns": "9.9.9.9, invalid-ip, 1.1.1.1\nserver=bad, 2606:4700:4700::1111",
            "block_message_default": "Bloqueado",
            "admin_contact": "suporte@exemplo.com",
            "wg_tunnel_mode": "full",
            "block_mode": "sinkhole",
            "admin_hosts": "",
        },
    )
    assert res.status_code == 200
    upstream_text = isolated_env["dns_upstream"].read_text(encoding="utf-8")
    assert "server=9.9.9.9" in upstream_text
    assert "server=1.1.1.1" in upstream_text
    assert "server=2606:4700:4700::1111" in upstream_text
    assert "invalid-ip" not in upstream_text
    assert "server=bad" not in upstream_text


def test_bulk_domains_returns_rejected_list(admin_client):
    res = admin_client.post(
        "/api/blocked-domains/bulk",
        data={
            "domains_text": "valido1.com\ninvalido sem tld\nhttps://valido2.com/path\nfoo/bar",
            "category": "Geral",
            "reason": "Teste bulk",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["added_count"] == 2
    assert len(data["rejected"]) == 2
