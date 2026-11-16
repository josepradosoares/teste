from concurrent.futures import ThreadPoolExecutor

import database as db
import wg_manager


def test_concurrent_device_allocation_respects_limit_and_unique_ips(client):
    plans = db.list_plans()
    paid_plan = next(p for p in plans if p["price"] > 0)
    cid = db.create_client(
        name="Cliente Concorrente",
        email="conc@example.com",
        phone="",
        plan_id=paid_plan["id"],
        username="concuser",
        password="password123",
    )
    assert cid is not None
    max_devices = int(paid_plan["max_devices"])  # 5

    def try_alloc(idx: int):
        priv, pub = wg_manager.generate_wg_keypair()
        try:
            dev_id, ip = db.allocate_device(
                client_id=cid,
                name=f"Device {idx}",
                wg_public_key=pub,
                wg_private_key=priv,
                max_devices=max_devices,
            )
            return ("ok", dev_id, ip)
        except db.DeviceLimitError:
            return ("limit", None, None)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(try_alloc, range(10)))

    successes = [r for r in results if r[0] == "ok"]
    limits = [r for r in results if r[0] == "limit"]
    assert len(successes) == max_devices
    assert len(limits) == 10 - max_devices

    ips = [r[2] for r in successes]
    assert len(set(ips)) == max_devices


def test_client_config_uses_slash_32(client):
    free_plan = db.get_free_plan()
    cid = db.create_client(
        name="Cliente Config",
        email="cfg@example.com",
        phone="",
        plan_id=free_plan["id"],
        username="cfguser",
        password="password123",
    )
    priv, pub = wg_manager.generate_wg_keypair()
    dev_id, ip = db.allocate_device(cid, "Notebook", pub, priv, max_devices=1)
    dev = db.get_device_with_plan(dev_id)
    conf = wg_manager.build_client_config(dev)
    assert f"Address = {ip}/32," in conf
    assert "/24" not in conf
