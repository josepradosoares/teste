import database as db
import dns_manager


def _settings_form(**overrides):
    data = {
        "server_ip": "203.0.113.10",
        "upstream_dns": "1.1.1.1, 8.8.8.8",
        "block_message_default": "Bloqueado",
        "admin_contact": "suporte@exemplo.com",
        "wg_tunnel_mode": "full",
        "block_mode": "sinkhole",
        "admin_hosts": "",
    }
    data.update(overrides)
    return data


def test_youtube_adblock_enabled_by_default_only_in_paid_conf(client, isolated_env):
    db.update_setting("server_ip", "203.0.113.10")
    res = dns_manager.sync_dnsmasq_blocklist()
    assert res["success"] is True
    assert res["youtube_adblock"] is True

    paid_text = isolated_env["dns_paid"].read_text(encoding="utf-8")
    free_text = isolated_env["dns_free"].read_text(encoding="utf-8")

    for dom in dns_manager.YOUTUBE_AD_DOMAINS:
        # Silent block: null IPv4 + IPv6, never the sinkhole/block page IP
        assert f"address=/{dom}/0.0.0.0" in paid_text
        assert f"address=/{dom}/::" in paid_text
        assert f"address=/{dom}/203.0.113.10" not in paid_text
        assert f"address=/{dom}/" not in free_text


def test_youtube_adblock_silent_even_in_sinkhole_mode(client, isolated_env):
    db.update_setting("server_ip", "203.0.113.10")
    db.update_setting("block_mode", "sinkhole")
    dns_manager.sync_dnsmasq_blocklist()
    paid_text = isolated_env["dns_paid"].read_text(encoding="utf-8")
    assert "address=/doubleclick.net/0.0.0.0" in paid_text
    assert "address=/doubleclick.net/203.0.113.10" not in paid_text


def test_youtube_adblock_never_blocks_video_or_player_hosts():
    critical = {
        "youtube.com", "www.youtube.com", "m.youtube.com", "s.youtube.com",
        "youtubei.googleapis.com", "googlevideo.com", "ytimg.com", "i.ytimg.com",
        "ggpht.com", "googleapis.com", "google.com", "gstatic.com",
        "jnn-pa.googleapis.com", "youtube-nocookie.com",
    }
    for dom in dns_manager.YOUTUBE_AD_DOMAINS:
        assert dom not in critical
        # an ad entry must not be a parent of a critical host (dnsmasq matches subdomains)
        for c in critical:
            assert not c.endswith("." + dom), (dom, c)


def test_youtube_adblock_domains_are_valid_normalized():
    from validators import normalize_domain
    assert dns_manager.YOUTUBE_AD_DOMAINS
    assert len(set(dns_manager.YOUTUBE_AD_DOMAINS)) == len(dns_manager.YOUTUBE_AD_DOMAINS)
    for dom in dns_manager.YOUTUBE_AD_DOMAINS:
        assert normalize_domain(dom) == dom


def test_youtube_adblock_disabled_removes_rules(client, isolated_env):
    db.update_setting("youtube_adblock", "0")
    res = dns_manager.sync_dnsmasq_blocklist()
    assert res["youtube_adblock"] is False
    paid_text = isolated_env["dns_paid"].read_text(encoding="utf-8")
    # Domínio exclusivo do YouTube adblock não deve estar presente no conf
    assert "address=/ads.youtube.com/" not in paid_text
    # Domínio pré-semeado no banco (doubleclick.net) volta a ter a regra normal de sinkhole, não 0.0.0.0
    assert "address=/doubleclick.net/0.0.0.0" not in paid_text


def test_youtube_adblock_no_duplicate_lines_for_seeded_domains(client, isolated_env):
    db.update_setting("server_ip", "203.0.113.10")
    dns_manager.sync_dnsmasq_blocklist()
    paid_text = isolated_env["dns_paid"].read_text(encoding="utf-8")
    # doubleclick.net está no banco e em YOUTUBE_AD_DOMAINS. Deve ter apenas as linhas 0.0.0.0 e :: (silencioso)
    # e NÃO deve ter a linha com o IP do sinkhole (evita duplicatas e garante bloqueio silencioso sem tela)
    assert "address=/doubleclick.net/0.0.0.0" in paid_text
    assert "address=/doubleclick.net/::" in paid_text
    assert "address=/doubleclick.net/203.0.113.10" not in paid_text
    assert paid_text.count("address=/doubleclick.net/0.0.0.0") == 1


def test_settings_api_toggles_youtube_adblock(admin_client, isolated_env):
    res = admin_client.post("/api/settings", data=_settings_form(youtube_adblock="0"))
    assert res.status_code == 200
    assert db.get_settings()["youtube_adblock"] == "0"
    assert "address=/ads.youtube.com/" not in isolated_env["dns_paid"].read_text(encoding="utf-8")

    res = admin_client.post("/api/settings", data=_settings_form(youtube_adblock="1"))
    assert res.status_code == 200
    assert db.get_settings()["youtube_adblock"] == "1"
    assert "address=/ads.youtube.com/0.0.0.0" in isolated_env["dns_paid"].read_text(encoding="utf-8")


def test_settings_api_invalid_or_missing_youtube_adblock_keeps_current(admin_client):
    db.update_setting("youtube_adblock", "0")
    res = admin_client.post("/api/settings", data=_settings_form(youtube_adblock="banana"))
    assert res.status_code == 200
    assert db.get_settings()["youtube_adblock"] == "0"

    res = admin_client.post("/api/settings", data=_settings_form())
    assert res.status_code == 200
    assert db.get_settings()["youtube_adblock"] == "0"


def test_youtube_adblock_default_setting_seeded(client):
    assert db.get_settings().get("youtube_adblock") == "1"
