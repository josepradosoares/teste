import os
import random
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, Request, Form, Query, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import database as db
import dns_manager

# Initialize DB on startup
db.init_db()

# Seed mock logs if DB has fewer than 10 logs so dashboard is visually rich right away
def seed_mock_logs_if_empty():
    conn = db.get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM query_logs;")
    count = c.fetchone()[0]
    if count < 10:
        sample_clients = ["192.168.1.15", "192.168.1.22", "192.168.1.37", "192.168.1.89", "192.168.1.104"]
        sample_domains = [
            ("google.com", "ALLOWED"),
            ("github.com", "ALLOWED"),
            ("tiktok.com", "BLOCKED"),
            ("bet365.com", "BLOCKED"),
            ("api.whatsapp.com", "ALLOWED"),
            ("xvideos.com", "BLOCKED"),
            ("cloudflare.com", "ALLOWED"),
            ("netflix.com", "ALLOWED"),
            ("blaze.com", "BLOCKED"),
            ("youtube.com", "ALLOWED"),
            ("microsoft.com", "ALLOWED"),
            ("torrentz2eu.org", "BLOCKED")
        ]
        base_time = datetime.now()
        for i in range(120):
            client = random.choice(sample_clients)
            dom, status = random.choice(sample_domains)
            # Add some randomness to time within last 6 hours
            minute_offset = random.randint(1, 360)
            t = (base_time - timedelta(minutes=minute_offset)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute(
                "INSERT INTO query_logs (client_ip, domain, query_type, status, timestamp) VALUES (?, ?, 'A', ?, ?);",
                (client, dom, status, t)
            )
        conn.commit()
    conn.close()

seed_mock_logs_if_empty()

# Create FastAPI app
app = FastAPI(title="NetShield DNS Control Panel", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Helper to identify if request is an admin request or a sinkholed blocked domain request
def is_admin_host(host_header: str, settings: dict) -> bool:
    if not host_header:
        return True
    host = host_header.split(":")[0].lower()
    server_ip = settings.get("server_ip", "").strip()
    return host in ["localhost", "127.0.0.1", "0.0.0.0", server_ip]

# Root route
@app.get("/", response_class=HTMLResponse)
async def index_or_block(request: Request, domain: Optional[str] = None):
    settings = db.get_settings()
    host_header = request.headers.get("host", "")
    req_domain = domain or host_header.split(":")[0].lower()

    # Check if requested domain is in our blocked list
    blocked_info = db.get_blocked_domain_info(req_domain)
    
    # If explicitly requesting dashboard or coming via server direct IP
    if request.query_params.get("admin") == "1" or (is_admin_host(host_header, settings) and not domain and not blocked_info):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "settings": settings,
                "page_title": "NetShield DNS - Painel de Controle"
            }
        )

    # Otherwise, render the Block Page
    reason = blocked_info.get("reason") if blocked_info else settings.get("block_message_default")
    category = blocked_info.get("category") if blocked_info else "Política de Acesso"
    
    # Log hit in blocked_domains
    if blocked_info:
        db.increment_hits(req_domain)
        # Also log query
        client_ip = request.client.host if request.client else "127.0.0.1"
        db.log_query(client_ip=client_ip, domain=req_domain, status="BLOCKED")

    return templates.TemplateResponse(
        request=request,
        name="blocked.html",
        context={
            "domain": req_domain,
            "reason": reason,
            "category": category,
            "client_ip": request.client.host if request.client else "Desconhecido",
            "timestamp": datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            "contact_email": settings.get("admin_contact", "suporte@rede.local")
        }
    )

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    settings = db.get_settings()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "settings": settings,
            "page_title": "NetShield DNS - Painel de Controle"
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
            "client_ip": request.client.host if request.client else "127.0.0.1",
            "timestamp": datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            "contact_email": settings.get("admin_contact", "suporte@rede.local")
        }
    )

# ==================== API ENDPOINTS ====================

@app.get("/api/stats")
async def get_stats():
    return db.get_stats()

@app.get("/api/blocked-domains")
async def get_blocked_domains(search: Optional[str] = None):
    domains = db.list_blocked_domains(search=search)
    return {"domains": domains, "total": len(domains)}

@app.post("/api/blocked-domains")
async def add_domain(
    domain: str = Form(...),
    reason: str = Form(""),
    category: str = Form("Geral")
):
    clean_domain = domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="O nome do domínio não pode ser vazio.")
    
    success = db.add_blocked_domain(domain=clean_domain, reason=reason, category=category)
    if not success:
        raise HTTPException(status_code=409, detail="Este domínio já está cadastrado na lista de bloqueios.")

    # Automatically synchronize with dnsmasq
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "domain": clean_domain, "sync": sync_result}

@app.post("/api/blocked-domains/{domain_id}/toggle")
async def toggle_domain(domain_id: int):
    new_state = db.toggle_blocked_domain(domain_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")
    
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "enabled": new_state, "sync": sync_result}

@app.delete("/api/blocked-domains/{domain_id}")
async def delete_domain(domain_id: int):
    deleted = db.delete_blocked_domain(domain_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Domínio não encontrado.")
    
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "sync": sync_result}

@app.post("/api/blocked-domains/bulk")
async def bulk_add_domains(domains_text: str = Form(...), category: str = Form("Geral"), reason: str = Form("Bloqueio em massa")):
    lines = [line.strip().lower() for line in domains_text.splitlines() if line.strip()]
    added_count = 0
    for dom in lines:
        if db.add_blocked_domain(dom, reason=reason, category=category):
            added_count += 1
    
    sync_result = dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "added_count": added_count, "total_submitted": len(lines), "sync": sync_result}

@app.get("/api/logs")
async def get_logs(limit: int = 50, filter_status: Optional[str] = None, search: Optional[str] = None):
    # Try parsing real dnsmasq logs if available
    dns_manager.parse_dnsmasq_log_stream()
    logs = db.get_recent_logs(limit=limit, filter_status=filter_status, search=search)
    return {"logs": logs, "count": len(logs)}

@app.post("/api/sync-dns")
async def force_sync_dns():
    res = dns_manager.sync_dnsmasq_blocklist()
    return res

@app.get("/api/settings")
async def get_settings():
    return db.get_settings()

@app.post("/api/settings")
async def update_settings(
    server_ip: str = Form(...),
    upstream_dns: str = Form(...),
    block_message_default: str = Form(...),
    admin_contact: str = Form(...)
):
    db.update_setting("server_ip", server_ip.strip())
    db.update_setting("upstream_dns", upstream_dns.strip())
    db.update_setting("block_message_default", block_message_default.strip())
    db.update_setting("admin_contact", admin_contact.strip())
    
    # Re-sync DNS config with new server IP
    dns_manager.sync_dnsmasq_blocklist()
    return {"success": True, "message": "Configurações atualizadas com sucesso."}

@app.post("/api/unblock-request")
async def submit_unblock_request(
    domain: str = Form(...),
    reason: str = Form(...),
    request: Request = None
):
    client_ip = request.client.host if request and request.client else "Desconhecido"
    db.create_unblock_request(domain=domain, client_ip=client_ip, reason=reason)
    return {"success": True, "message": "Solicitação enviada ao administrador da rede."}

@app.get("/api/unblock-requests")
async def get_unblock_requests():
    reqs = db.list_unblock_requests()
    return {"requests": reqs, "total": len(reqs)}
