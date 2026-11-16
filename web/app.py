import os
import json
import hmac
import hashlib
import base64
import time
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Form, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import database as db
import dns_manager
import wg_manager

# Initialize DB on startup
db.init_db()

app = FastAPI(title="NetShield DNS Commercial Platform", version="2.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

SESSION_COOKIE_NAME = "netshield_session"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days

# ==================== SESSION / AUTH HELPERS ====================

def _get_secret() -> bytes:
    settings = db.get_settings()
    return settings.get("session_secret", "netshield-fallback-secret").encode("utf-8")

def create_session_token(user_id: int, role: str) -> str:
    payload = {
        "uid": user_id,
        "role": role,
        "exp": int(time.time()) + SESSION_TTL_SECONDS
    }
    b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    sig = hmac.new(_get_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"

def decode_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token or "." not in token:
        return None
    try:
        b64, sig = token.split(".", 1)
        expected_sig = hmac.new(_get_secret(), b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(b64.encode("utf-8")).decode("utf-8"))
        if payload.get("exp", 0) < int(time.time()):
            return None
        user = db.get_user_by_id(payload["uid"])
        if not user or user.get("is_active") != 1:
            return None
        return user
    except Exception:
        return None

def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    return decode_session_token(token)

def require_admin(request: Request) -> Dict[str, Any]:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Autenticação necessária.")
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito ao administrador.")
    return user

def require_auth(request: Request) -> Dict[str, Any]:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Autenticação necessária.")
    return user

# Helper to identify if request is an admin/portal host or a sinkholed blocked domain request
def is_admin_host(host_header: str, settings: dict) -> bool:
    if not host_header:
        return True
    host = host_header.split(":")[0].lower()
    server_ip = settings.get("server_ip", "").strip().lower()
    if host in ["localhost", "127.0.0.1", "0.0.0.0", "testserver", server_ip]:
        return True
    if host.endswith(".duckdns.org") or host.endswith(".ddns.net") or "painel" in host:
        return True
    return False

def get_real_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    real_ip = request.headers.get("x-real-ip")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"

# ==================== PUBLIC & PAGE ROUTES ====================

@app.get("/", response_class=HTMLResponse)
async def index_or_block(request: Request, domain: Optional[str] = None):
    settings = db.get_settings()
    host_header = request.headers.get("host", "")
    req_domain = domain or host_header.split(":")[0].lower()

    blocked_info = db.get_blocked_domain_info(req_domain)

    # If coming via server IP, DuckDNS domain, or explicit ?admin=1
    if request.query_params.get("admin") == "1" or (is_admin_host(host_header, settings) and not domain and not blocked_info):
        user = get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        if user.get("role") == "admin":
            return RedirectResponse(url="/admin", status_code=302)
        return RedirectResponse(url="/cliente", status_code=302)

    # Otherwise, render the Block Page
    reason = blocked_info.get("reason") if blocked_info else settings.get("block_message_default")
    category = blocked_info.get("category") if blocked_info else "Política de Acesso"

    if blocked_info:
        db.increment_hits(req_domain)
        client_ip = get_real_client_ip(request)
        db.log_query(client_ip=client_ip, domain=req_domain, status="BLOCKED")

    return templates.TemplateResponse(
        request=request,
        name="blocked.html",
        context={
            "domain": req_domain,
            "reason": reason,
            "category": category,
            "client_ip": get_real_client_ip(request),
            "timestamp": datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            "contact_email": settings.get("admin_contact", "suporte@rede.local")
        }
    )

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/admin" if user["role"] == "admin" else "/cliente", status_code=302)
    initial_mode = "register" if request.query_params.get("mode") == "register" else "login"
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"page_title": "Entrar | NetShield DNS", "initial_mode": initial_mode}
    )

@app.get("/gratis", response_class=HTMLResponse)
async def free_signup_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/admin" if user["role"] == "admin" else "/cliente", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"page_title": "Versão Free Gratuita | NetShield DNS", "initial_mode": "register"}
    )

@app.get("/logout")
async def logout_route():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user.get("role") != "admin":
        return RedirectResponse(url="/cliente", status_code=302)

    settings = db.get_settings()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "settings": settings,
            "user": user,
            "page_title": "NetShield DNS - Painel Administrativo"
        }
    )

@app.get("/cliente", response_class=HTMLResponse)
async def client_portal(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    if user.get("role") == "admin":
        return RedirectResponse(url="/admin", status_code=302)

    client_info = db.get_client_by_user_id(user["id"])
    devices = db.list_devices(client_info["id"]) if client_info else []
    settings = db.get_settings()

    return templates.TemplateResponse(
        request=request,
        name="client_portal.html",
        context={
            "user": user,
            "client": client_info,
            "devices": devices,
            "settings": settings,
            "page_title": "Portal do Assinante | NetShield DNS"
        }
    )

@app.get("/blocked", response_class=HTMLResponse)
async def explicit_blocked_page(request: Request, domain: str = "sitebloqueado.com"):
    settings = db.get_settings()
    blocked_info = db.get_blocked_domain_info(domain)
    reason = blocked_info.get("reason") if blocked_info else settings.get("block_message_default")
    category = blocked_info.get("category") if blocked_info else "Restrição Administrativa"

    return templates.TemplateResponse(
        request=request,
        name="blocked.html",
        context={
            "domain": domain,
            "reason": reason,
            "category": category,
            "client_ip": get_real_client_ip(request),
            "timestamp": datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            "contact_email": settings.get("admin_contact", "suporte@rede.local")
        }
    )

# ==================== AUTH API ====================

@app.post("/api/auth/login")
async def api_login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = db.get_user_by_username(username)
    if not user or not db.verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuário ou senha incorretos.")
    if user.get("is_active") != 1:
        raise HTTPException(status_code=403, detail="Conta desativada.")

    token = create_session_token(user["id"], user["role"])
    redirect_to = "/admin" if user["role"] == "admin" else "/cliente"
    resp = JSONResponse({"success": True, "role": user["role"], "redirect": redirect_to})
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS
    )
    return resp

@app.post("/api/auth/register-free")
async def api_register_free(
    name: str = Form(...),
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    device_name: str = Form("Meu Dispositivo")
):
    clean_name = name.strip()
    clean_email = email.strip()
    clean_username = username.strip().lower()
    clean_device = device_name.strip() or "Meu Dispositivo"

    if len(clean_name) < 2:
        raise HTTPException(status_code=400, detail="Informe seu nome completo.")
    if "@" not in clean_email or "." not in clean_email:
        raise HTTPException(status_code=400, detail="Informe um e-mail válido.")
    if len(clean_username) < 3 or not clean_username.replace("_", "").replace(".", "").isalnum():
        raise HTTPException(status_code=400, detail="O usuário deve ter pelo menos 3 caracteres (letras, números, . ou _).")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="A senha deve ter pelo menos 6 caracteres.")

    free_plan = db.get_free_plan()
    if not free_plan:
        raise HTTPException(status_code=503, detail="Plano Free temporariamente indisponível.")

    client_id = db.create_client(
        name=clean_name,
        email=clean_email,
        phone="",
        plan_id=free_plan["id"],
        username=clean_username,
        password=password,
        notes="Cadastro automático - Versão Free"
    )
    if not client_id:
        raise HTTPException(status_code=409, detail="Este usuário já está em uso. Escolha outro login.")

    vpn_ip = db.get_next_vpn_ip()
    priv_key, pub_key = wg_manager.generate_wg_keypair()
    db.add_device(
        client_id=client_id,
        name=clean_device,
        vpn_ip=vpn_ip,
        wg_public_key=pub_key,
        wg_private_key=priv_key
    )
    wg_manager.sync_wireguard_peers()

    created_user = db.get_user_by_username(clean_username)
    resp = JSONResponse({
        "success": True,
        "role": "client",
        "redirect": "/cliente",
        "message": "Conta Free criada com sucesso!"
    })
    if created_user:
        token = create_session_token(created_user["id"], created_user["role"])
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_TTL_SECONDS
        )
    return resp

@app.post("/api/auth/change-password")
async def api_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...)
):
    user_session = require_auth(request)
    full_user = db.get_user_by_username(user_session["username"])
    if not full_user or not db.verify_password(current_password, full_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Senha atual incorreta.")
    if len(new_password.strip()) < 6:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 6 caracteres.")
    db.update_user_password(full_user["id"], new_password.strip())
    return {"success": True, "message": "Senha alterada com sucesso!"}

# ==================== STATS & DNS API (ADMIN) ====================

@app.get("/api/stats")
async def get_stats(request: Request):
    require_admin(request)
    return db.get_stats()

@app.get("/api/blocked-domains")
async def get_blocked_domains(request: Request, search: Optional[str] = None):
    require_admin(request)
    domains = db.list_blocked_domains(search=search)
    return {"domains": domains, "total": len(domains)}

@app.get("/api/categories")
async def get_categories(request: Request):
    require_admin(request)
    return {"categories": db.list_categories_summary()}

@app.post("/api/categories/toggle")
async def toggle_category(request: Request, category: str = Form(...), enable: int = Form(...)):
    require_admin(request)
    updated = db.toggle_category(category, enable)
    sync_res = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "updated": updated, "sync": sync_res}

@app.post("/api/blocked-domains")
async def add_domain(
    request: Request,
    domain: str = Form(...),
    reason: str = Form(""),
    category: str = Form("Geral"),
    free_included: int = Form(0)
):
    require_admin(request)
    clean_domain = domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="O nome do domínio não pode ser vazio.")

    success = db.add_blocked_domain(domain=clean_domain, reason=reason, category=category, free_included=free_included)
    if not success:
        raise HTTPException(status_code=409, detail="Este domínio já está cadastrado na lista de bloqueios.")

    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "domain": clean_domain, "sync": sync_result}

@app.put("/api/blocked-domains/{domain_id}")
async def update_domain(
    request: Request,
    domain_id: int,
    domain: str = Form(...),
    category: str = Form("Geral"),
    reason: str = Form("Acesso bloqueado pelo administrador."),
    free_included: int = Form(0)
):
    require_admin(request)
    ok = db.update_blocked_domain(domain_id=domain_id, domain=domain, category=category, reason=reason, free_included=free_included)
    if not ok:
        raise HTTPException(status_code=400, detail="Domínio inválido, duplicado ou regra não encontrada.")
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "sync": sync_result}

@app.post("/api/blocked-domains/{domain_id}/toggle-free")
async def toggle_domain_free(request: Request, domain_id: int):
    require_admin(request)
    new_state = db.toggle_blocked_domain_free(domain_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "free_included": new_state, "sync": sync_result}

@app.post("/api/blocked-domains/{domain_id}/toggle")
async def toggle_domain(request: Request, domain_id: int):
    require_admin(request)
    new_state = db.toggle_blocked_domain(domain_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "enabled": new_state, "sync": sync_result}

@app.delete("/api/blocked-domains/{domain_id}")
async def delete_domain(request: Request, domain_id: int):
    require_admin(request)
    deleted = db.delete_blocked_domain(domain_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")

    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "sync": sync_result}

@app.post("/api/blocked-domains/bulk")
async def bulk_add_domains(
    request: Request,
    domains_text: str = Form(...),
    category: str = Form("Geral"),
    reason: str = Form("Bloqueio em massa"),
    free_included: int = Form(0)
):
    require_admin(request)
    lines = [line.strip().lower() for line in domains_text.splitlines() if line.strip()]
    added_count = 0
    for dom in lines:
        if db.add_blocked_domain(dom, reason=reason, category=category, free_included=free_included):
            added_count += 1

    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "added_count": added_count, "total_submitted": len(lines), "sync": sync_result}

@app.get("/api/logs")
async def get_logs(request: Request, limit: int = 50, filter_status: Optional[str] = None, search: Optional[str] = None):
    require_admin(request)
    dns_manager.parse_dnsmasq_log_stream()
    logs = db.get_recent_logs(limit=limit, filter_status=filter_status, search=search)
    return {"logs": logs, "count": len(logs)}

@app.post("/api/sync-dns")
async def force_sync_dns(request: Request):
    require_admin(request)
    return dns_manager.sync_dnsmasq_blocklist()

@app.get("/api/settings")
async def get_settings(request: Request):
    require_admin(request)
    s = db.get_settings()
    s.pop("session_secret", None)
    return s

@app.post("/api/settings")
async def update_settings(
    request: Request,
    server_ip: str = Form(...),
    upstream_dns: str = Form(...),
    block_message_default: str = Form(...),
    admin_contact: str = Form(...),
    wg_tunnel_mode: str = Form("full")
):
    require_admin(request)
    mode = wg_tunnel_mode.strip() if wg_tunnel_mode.strip() in ["full", "dns_only"] else "full"
    db.update_setting("server_ip", server_ip.strip())
    db.update_setting("upstream_dns", upstream_dns.strip())
    db.update_setting("block_message_default", block_message_default.strip())
    db.update_setting("admin_contact", admin_contact.strip())
    db.update_setting("wg_tunnel_mode", mode)

    dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "message": "Configurações atualizadas com sucesso."}

# ==================== PLANS API (ADMIN) ====================

@app.get("/api/plans")
async def api_list_plans(request: Request):
    require_admin(request)
    return {"plans": db.list_plans()}

@app.post("/api/plans")
async def api_create_plan(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    price: float = Form(...),
    duration_days: int = Form(30),
    max_devices: int = Form(2)
):
    require_admin(request)
    plan_id = db.create_plan(name=name, description=description, price=price, duration_days=duration_days, max_devices=max_devices)
    if not plan_id:
        raise HTTPException(status_code=409, detail="Já existe um plano com esse nome.")
    return {"success": True, "plan_id": plan_id}

@app.put("/api/plans/{plan_id}")
async def api_update_plan(
    request: Request,
    plan_id: int,
    name: str = Form(...),
    description: str = Form(""),
    price: float = Form(...),
    duration_days: int = Form(30),
    max_devices: int = Form(2)
):
    require_admin(request)
    if not db.update_plan(plan_id=plan_id, name=name, description=description, price=price, duration_days=duration_days, max_devices=max_devices):
        raise HTTPException(status_code=400, detail="Erro ao atualizar plano ou nome já existente.")
    return {"success": True}

@app.post("/api/plans/{plan_id}/toggle")
async def api_toggle_plan(request: Request, plan_id: int):
    require_admin(request)
    val = db.toggle_plan(plan_id)
    if val is None:
        raise HTTPException(status_code=404, detail="Plano não encontrado.")
    return {"success": True, "is_active": val}

@app.delete("/api/plans/{plan_id}")
async def api_delete_plan(request: Request, plan_id: int):
    require_admin(request)
    if not db.delete_plan(plan_id):
        raise HTTPException(status_code=404, detail="Plano não encontrado.")
    return {"success": True}

# ==================== CLIENTS & WIREGUARD PROVISIONING API ====================

@app.get("/api/clients")
async def api_list_clients(request: Request, search: Optional[str] = None):
    require_admin(request)
    clients = db.list_clients(search=search)
    return {"clients": clients, "total": len(clients)}

@app.post("/api/clients")
async def api_create_client(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(""),
    plan_id: int = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    notes: str = Form(""),
    auto_create_device: int = Form(1)
):
    require_admin(request)
    client_id = db.create_client(
        name=name,
        email=email,
        phone=phone,
        plan_id=plan_id,
        username=username,
        password=password,
        notes=notes
    )
    if not client_id:
        raise HTTPException(status_code=409, detail="Nome de usuário já está em uso.")

    device_id = None
    if auto_create_device == 1:
        priv, pub = wg_manager.generate_wg_keypair()
        vpn_ip = db.get_next_vpn_ip()
        device_id = db.add_device(
            client_id=client_id,
            name="Dispositivo Principal",
            vpn_ip=vpn_ip,
            wg_public_key=pub,
            wg_private_key=priv
        )
        wg_manager.sync_wireguard_peers()

    return {"success": True, "client_id": client_id, "device_id": device_id}

@app.put("/api/clients/{client_id}")
async def api_update_client(
    request: Request,
    client_id: int,
    name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(""),
    plan_id: int = Form(...),
    status: str = Form("ACTIVE"),
    expires_at: str = Form(...),
    notes: str = Form(""),
    new_password: str = Form("")
):
    require_admin(request)
    if new_password and len(new_password.strip()) < 6:
        raise HTTPException(status_code=400, detail="A nova senha deve ter pelo menos 6 caracteres.")
    ok = db.update_client(
        client_id=client_id,
        name=name,
        email=email,
        phone=phone,
        plan_id=plan_id,
        status=status,
        expires_at=expires_at,
        notes=notes,
        new_password=new_password
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Não foi possível atualizar o cliente.")
    sync_res = wg_manager.sync_wireguard_peers()
    return {"success": True, "wg_sync": sync_res}

@app.post("/api/clients/{client_id}/status")
async def api_update_client_status(request: Request, client_id: int, status: str = Form(...)):
    require_admin(request)
    if not db.update_client_status(client_id, status):
        raise HTTPException(status_code=400, detail="Status inválido ou cliente não encontrado.")
    sync_res = wg_manager.sync_wireguard_peers()
    return {"success": True, "status": status, "wg_sync": sync_res}

@app.post("/api/clients/{client_id}/renew")
async def api_renew_client(request: Request, client_id: int, extra_days: Optional[int] = Form(None)):
    require_admin(request)
    new_exp = db.renew_client(client_id, extra_days=extra_days)
    if not new_exp:
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
    sync_res = wg_manager.sync_wireguard_peers()
    return {"success": True, "expires_at": new_exp, "wg_sync": sync_res}

@app.delete("/api/clients/{client_id}")
async def api_delete_client(request: Request, client_id: int):
    require_admin(request)
    if not db.delete_client(client_id):
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
    wg_manager.sync_wireguard_peers()
    return {"success": True}

@app.get("/api/clients/{client_id}/devices")
async def api_client_devices(request: Request, client_id: int):
    user = require_auth(request)
    if user["role"] != "admin":
        client = db.get_client_by_user_id(user["id"])
        if not client or client["id"] != client_id:
            raise HTTPException(status_code=403, detail="Acesso negado.")
    devices = db.list_devices(client_id=client_id)
    return {"devices": devices}

@app.post("/api/clients/{client_id}/devices")
async def api_add_client_device(request: Request, client_id: int, name: str = Form(...)):
    user = require_auth(request)
    client = db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")

    if user["role"] != "admin":
        own_client = db.get_client_by_user_id(user["id"])
        if not own_client or own_client["id"] != client_id:
            raise HTTPException(status_code=403, detail="Acesso negado.")

    existing = db.list_devices(client_id=client_id)
    max_dev = client.get("max_devices") or 2
    if len(existing) >= max_dev:
        raise HTTPException(status_code=400, detail=f"Limite de {max_dev} dispositivo(s) do plano atingido.")

    priv, pub = wg_manager.generate_wg_keypair()
    vpn_ip = db.get_next_vpn_ip()
    device_id = db.add_device(
        client_id=client_id,
        name=name,
        vpn_ip=vpn_ip,
        wg_public_key=pub,
        wg_private_key=priv
    )
    wg_manager.sync_wireguard_peers()
    return {"success": True, "device_id": device_id, "vpn_ip": vpn_ip}

@app.get("/api/devices/{device_id}/qr")
async def api_device_qr(request: Request, device_id: int):
    user = require_auth(request)
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    if user["role"] != "admin":
        client = db.get_client_by_user_id(user["id"])
        if not client or client["id"] != device["client_id"]:
            raise HTTPException(status_code=403, detail="Acesso negado.")

    config_text = wg_manager.build_client_config(device)
    qr_svg = wg_manager.generate_qr_svg(config_text)
    return {
        "device": device,
        "config_text": config_text,
        "qr_svg": qr_svg
    }

@app.get("/api/devices/{device_id}/config")
async def api_download_device_config(request: Request, device_id: int):
    user = require_auth(request)
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    if user["role"] != "admin":
        client = db.get_client_by_user_id(user["id"])
        if not client or client["id"] != device["client_id"]:
            raise HTTPException(status_code=403, detail="Acesso negado.")

    config_text = wg_manager.build_client_config(device)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in device["name"].lower())
    return PlainTextResponse(
        content=config_text,
        headers={"Content-Disposition": f"attachment; filename=netshield_{safe_name}.conf"}
    )

@app.put("/api/devices/{device_id}")
async def api_rename_device(request: Request, device_id: int, name: str = Form(...)):
    user = require_auth(request)
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")
    if user["role"] != "admin":
        client = db.get_client_by_user_id(user["id"])
        if not client or client["id"] != device["client_id"]:
            raise HTTPException(status_code=403, detail="Acesso negado.")
    if not name.strip():
        raise HTTPException(status_code=400, detail="Informe o novo nome do dispositivo.")
    db.rename_device(device_id, name)
    return {"success": True}

@app.delete("/api/devices/{device_id}")
async def api_delete_device(request: Request, device_id: int):
    user = require_auth(request)
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    if user["role"] != "admin":
        client = db.get_client_by_user_id(user["id"])
        if not client or client["id"] != device["client_id"]:
            raise HTTPException(status_code=403, detail="Acesso negado.")

    db.delete_device(device_id)
    wg_manager.sync_wireguard_peers()
    return {"success": True}

# ==================== UNBLOCK REQUESTS ====================

@app.post("/api/unblock-request")
async def submit_unblock_request(
    domain: str = Form(...),
    reason: str = Form(...),
    request: Request = None
):
    client_ip = get_real_client_ip(request) if request else "Desconhecido"
    db.create_unblock_request(domain=domain, client_ip=client_ip, reason=reason)
    return {"success": True, "message": "Solicitação enviada ao administrador da rede."}

@app.get("/api/unblock-requests")
async def get_unblock_requests(request: Request):
    require_admin(request)
    reqs = db.list_unblock_requests()
    return {"requests": reqs, "total": len(reqs)}

@app.delete("/api/unblock-requests/{request_id}")
async def delete_unblock_request_route(request: Request, request_id: int):
    require_admin(request)
    if not db.delete_unblock_request(request_id):
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return {"success": True}

# ==================== CATCH-ALL FALLBACK (MOBILE & SUBPATHS) ====================

@app.api_route("/{full_path:path}", methods=["GET", "POST", "HEAD"], response_class=HTMLResponse)
async def catch_all_fallback(request: Request, full_path: str):
    # Preserve JSON 404 for unknown /api/* endpoints
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Endpoint não encontrado.")

    settings = db.get_settings()
    host_header = request.headers.get("host", "")
    req_domain = host_header.split(":")[0].lower()
    blocked_info = db.get_blocked_domain_info(req_domain)

    # If the request came for a blocked domain (even on deep subpaths like /explore or /login)
    if not is_admin_host(host_header, settings) or blocked_info:
        reason = blocked_info.get("reason") if blocked_info else settings.get("block_message_default")
        category = blocked_info.get("category") if blocked_info else "Política de Acesso"

        if blocked_info:
            db.increment_hits(req_domain)
            db.log_query(client_ip=get_real_client_ip(request), domain=req_domain, status="BLOCKED")

        return templates.TemplateResponse(
            request=request,
            name="blocked.html",
            context={
                "domain": req_domain,
                "reason": reason,
                "category": category,
                "client_ip": get_real_client_ip(request),
                "timestamp": datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
                "contact_email": settings.get("admin_contact", "suporte@rede.local")
            }
        )

    # Unknown route on the panel/admin host -> friendly mobile-responsive 404 page
    return templates.TemplateResponse(
        request=request,
        name="not_found.html",
        status_code=404,
        context={
            "requested_path": f"/{full_path}",
            "contact_email": settings.get("admin_contact", "suporte@rede.local")
        }
    )
