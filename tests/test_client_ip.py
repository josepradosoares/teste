def test_x_forwarded_for_is_ignored_and_x_real_ip_is_used(client, admin_client):
    res = client.post(
        "/api/unblock-request",
        data={"domain": "exemplo.com", "reason": "Teste de IP real"},
        headers={
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "177.55.66.77",
        },
    )
    assert res.status_code == 200

    reqs = admin_client.get("/api/unblock-requests").json()["requests"]
    assert len(reqs) == 1
    assert reqs[0]["client_ip"] == "177.55.66.77"
