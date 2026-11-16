import database as db


def test_delete_plan_with_clients_returns_409(admin_client):
    free_plan = db.get_free_plan()
    cid = db.create_client(
        name="Cliente Plano",
        email="plano@example.com",
        phone="",
        plan_id=free_plan["id"],
        username="planuser",
        password="password123",
    )
    assert cid is not None

    res = admin_client.delete(f"/api/plans/{free_plan['id']}")
    assert res.status_code == 409


def test_free_plan_never_expires_while_paid_plan_expires(client):
    free_plan = db.get_free_plan()
    paid_plan = next(p for p in db.list_plans() if p["price"] > 0)

    free_cid = db.create_client(
        name="Cliente Free",
        email="free@example.com",
        phone="",
        plan_id=free_plan["id"],
        username="freeforever",
        password="password123",
    )
    paid_cid = db.create_client(
        name="Cliente Pago",
        email="paid@example.com",
        phone="",
        plan_id=paid_plan["id"],
        username="paidexpiring",
        password="password123",
    )

    # Set both expires_at in the past
    conn = db.get_db()
    conn.execute("UPDATE clients SET expires_at = '2020-01-01 00:00:00' WHERE id IN (?, ?);", (free_cid, paid_cid))
    conn.commit()
    conn.close()

    changed = db.refresh_expired_clients()
    assert changed == 1

    free_client = db.get_client(free_cid)
    paid_client = db.get_client(paid_cid)
    assert free_client["status"] == "ACTIVE"
    assert paid_client["status"] == "EXPIRED"
