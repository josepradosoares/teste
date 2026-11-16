from fastapi.testclient import TestClient

import app as web_app


def test_admin_with_admin123_is_forced_to_change_password(isolated_env, monkeypatch):
    monkeypatch.setenv("NETSHIELD_ADMIN_PASSWORD", "admin123")
    with TestClient(web_app.app) as c:
        login_res = c.post(
            "/api/auth/login",
            data={"username": "admin", "password": "admin123"},
            headers={"X-Real-IP": "198.51.100.20"},
        )
        assert login_res.status_code == 200
        assert login_res.json()["must_change_password"] is True

        # Admin APIs must return 403 with must_change_password=True
        stats_res = c.get("/api/stats")
        assert stats_res.status_code == 403
        assert stats_res.json()["must_change_password"] is True

        # Changing password to a strong one unlocks admin APIs
        chg_res = c.post(
            "/api/auth/change-password",
            data={"current_password": "admin123", "new_password": "NewStrongPassword!9"},
        )
        assert chg_res.status_code == 200

        stats_after = c.get("/api/stats")
        assert stats_after.status_code == 200


def test_login_rate_limit_sixth_attempt_returns_429(client):
    for i in range(5):
        res = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": f"wrong{i}"},
            headers={"X-Real-IP": "203.0.113.50"},
        )
        assert res.status_code == 401

    res6 = client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "wrong5"},
        headers={"X-Real-IP": "203.0.113.50"},
    )
    assert res6.status_code == 429


def test_old_session_invalidated_after_password_change(isolated_env):
    with TestClient(web_app.app) as c1, TestClient(web_app.app) as c2:
        r1 = c1.post(
            "/api/auth/login",
            data={"username": "admin", "password": "StrongTestPass!123"},
            headers={"X-Real-IP": "198.51.100.31"},
        )
        r2 = c2.post(
            "/api/auth/login",
            data={"username": "admin", "password": "StrongTestPass!123"},
            headers={"X-Real-IP": "198.51.100.32"},
        )
        assert r1.status_code == 200 and r2.status_code == 200
        assert c2.get("/api/stats").status_code == 200

        # c1 changes password -> c2's old session_version becomes invalid
        chg = c1.post(
            "/api/auth/change-password",
            data={"current_password": "StrongTestPass!123", "new_password": "AnotherStrongPass!456"},
        )
        assert chg.status_code == 200
        assert c1.get("/api/stats").status_code == 200
        assert c2.get("/api/stats").status_code == 401


def test_register_free_and_unblock_rate_limits(client):
    for i in range(3):
        r = client.post(
            "/api/auth/register-free",
            data={
                "name": f"Usuario {i}",
                "email": f"u{i}@example.com",
                "username": f"freeuser{i}",
                "password": "password123",
                "device_name": "Celular",
            },
            headers={"X-Real-IP": "198.51.100.40"},
        )
        assert r.status_code == 200

    r4 = client.post(
        "/api/auth/register-free",
        data={
            "name": "Usuario 3",
            "email": "u3@example.com",
            "username": "freeuser3",
            "password": "password123",
            "device_name": "Celular",
        },
        headers={"X-Real-IP": "198.51.100.40"},
    )
    assert r4.status_code == 429

    for i in range(5):
        u = client.post(
            "/api/unblock-request",
            data={"domain": f"site{i}.com", "reason": "Preciso acessar"},
            headers={"X-Real-IP": "198.51.100.41"},
        )
        assert u.status_code == 200

    u6 = client.post(
        "/api/unblock-request",
        data={"domain": "site5.com", "reason": "Preciso acessar"},
        headers={"X-Real-IP": "198.51.100.41"},
    )
    assert u6.status_code == 429
