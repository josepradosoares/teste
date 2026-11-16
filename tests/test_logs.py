import dns_manager


def test_logs_limit_above_500_returns_422(admin_client):
    res = admin_client.get("/api/logs?limit=100000")
    assert res.status_code == 422


def test_log_parser_caps_bytes_per_call(client, isolated_env):
    # Write a 2.5 MB log file after initial position; single parse call must read <= 2 MB
    line = "Nov 16 12:00:00 dnsmasq[123]: query[A] example.com from 10.8.0.2\n"
    repeat = (2_500_000 // len(line)) + 1
    isolated_env["dns_log"].write_text(line * repeat, encoding="utf-8")
    dns_manager._last_log_position = 1

    dns_manager.parse_dnsmasq_log_stream()
    assert dns_manager._last_log_position <= 1 + dns_manager.MAX_LOG_READ_BYTES + len(line)
