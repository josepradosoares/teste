// NetShield DNS Commercial Platform - Client-side Application Logic
document.addEventListener("DOMContentLoaded", () => {
  let autoRefreshTimer = null;
  let activeTab = "tab-logs";

  const tabs = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const toastContainer = document.getElementById("toastContainer");

  // KPI Elements
  const statActiveSubscribers = document.getElementById("statActiveSubscribers");
  const statMrr = document.getElementById("statMrr");
  const statTotalDevices = document.getElementById("statTotalDevices");
  const statTotalQueries = document.getElementById("statTotalQueries");
  const statTotalBlocked = document.getElementById("statTotalBlocked");
  const statBlockRate = document.getElementById("statBlockRate");
  const statActiveRules = document.getElementById("statActiveRules");

  const badgeLogCount = document.getElementById("badgeLogCount");
  const badgeClientCount = document.getElementById("badgeClientCount");
  const badgePlanCount = document.getElementById("badgePlanCount");
  const badgeDomainCount = document.getElementById("badgeDomainCount");
  const badgeRequestCount = document.getElementById("badgeRequestCount");

  // Logs Elements
  const logsTableBody = document.getElementById("logsTableBody");
  const logSearchInput = document.getElementById("logSearchInput");
  const logStatusFilter = document.getElementById("logStatusFilter");
  const btnRefreshLogs = document.getElementById("btnRefreshLogs");
  const autoRefreshCheckbox = document.getElementById("autoRefreshCheckbox");

  // Clients Elements
  const clientsTableBody = document.getElementById("clientsTableBody");
  const clientSearchInput = document.getElementById("clientSearchInput");
  const btnOpenAddClientModal = document.getElementById("btnOpenAddClientModal");
  const addClientModal = document.getElementById("addClientModal");
  const closeAddClientModal = document.getElementById("closeAddClientModal");
  const cancelAddClientBtn = document.getElementById("cancelAddClientBtn");
  const addClientForm = document.getElementById("addClientForm");
  const clientPlanSelect = document.getElementById("clientPlanSelect");
  const clientDevicesModal = document.getElementById("clientDevicesModal");
  const clientDevicesTableBody = document.getElementById("clientDevicesTableBody");
  const adminAddDeviceForm = document.getElementById("adminAddDeviceForm");

  // Plans Elements
  const plansGrid = document.getElementById("plansGrid");
  const btnOpenAddPlanModal = document.getElementById("btnOpenAddPlanModal");
  const addPlanModal = document.getElementById("addPlanModal");
  const closeAddPlanModal = document.getElementById("closeAddPlanModal");
  const cancelAddPlanBtn = document.getElementById("cancelAddPlanBtn");
  const addPlanForm = document.getElementById("addPlanForm");

  // Domains & Categories Elements
  const categoriesGrid = document.getElementById("categoriesGrid");
  const domainsTableBody = document.getElementById("domainsTableBody");
  const domainSearchInput = document.getElementById("domainSearchInput");
  const btnOpenAddModal = document.getElementById("btnOpenAddModal");
  const btnOpenBulkModal = document.getElementById("btnOpenBulkModal");
  const addDomainModal = document.getElementById("addDomainModal");
  const closeAddModal = document.getElementById("closeAddModal");
  const cancelAddBtn = document.getElementById("cancelAddBtn");
  const addDomainForm = document.getElementById("addDomainForm");
  const bulkModal = document.getElementById("bulkModal");
  const closeBulkModal = document.getElementById("closeBulkModal");
  const cancelBulkBtn = document.getElementById("cancelBulkBtn");
  const bulkForm = document.getElementById("bulkForm");

  // Requests & Settings
  const requestsTableBody = document.getElementById("requestsTableBody");
  const btnRefreshRequests = document.getElementById("btnRefreshRequests");
  const settingsForm = document.getElementById("settingsForm");
  const changePasswordForm = document.getElementById("changePasswordForm");
  const btnSyncDns = document.getElementById("btnSyncDns");

  function showToast(message, type = "success") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "success" ? "✓" : "⚠";
    toast.innerHTML = `<span style="font-weight:bold;">${icon}</span> <span>${escapeHtml(message)}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 300ms ease";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function handleAuthError(res) {
    if (res.status === 401) {
      window.location.href = "/login";
      return true;
    }
    return false;
  }

  // Tab Switching
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      tab.classList.add("active");
      activeTab = tab.getAttribute("data-tab");
      const targetContent = document.getElementById(activeTab);
      if (targetContent) targetContent.classList.add("active");

      if (activeTab === "tab-logs") loadQueryLogs();
      if (activeTab === "tab-clients") loadClients();
      if (activeTab === "tab-plans") loadPlans();
      if (activeTab === "tab-domains") {
        loadCategories();
        loadBlockedDomains();
      }
      if (activeTab === "tab-requests") loadUnblockRequests();
    });
  });

  // Load KPI Stats
  async function loadStats() {
    try {
      const res = await fetch("/api/stats");
      if (handleAuthError(res) || !res.ok) return;
      const data = await res.json();
      statActiveSubscribers.textContent = (data.active_subscribers || 0).toLocaleString();
      statMrr.textContent = `R$ ${(data.mrr || 0).toFixed(2).replace(".", ",")}`;
      statTotalDevices.textContent = (data.total_devices || 0).toLocaleString();
      statTotalQueries.textContent = (data.total_queries || 0).toLocaleString();
      statTotalBlocked.textContent = (data.total_blocked || 0).toLocaleString();
      statBlockRate.textContent = `${data.block_rate || 0}%`;
      statActiveRules.textContent = (data.active_blocked_domains || 0).toLocaleString();
      badgeDomainCount.textContent = data.active_blocked_domains || 0;
    } catch (e) {
      console.error("Error loading stats:", e);
    }
  }

  // ==================== LOGS ====================
  async function loadQueryLogs() {
    try {
      const search = logSearchInput.value.trim();
      const status = logStatusFilter.value;
      let url = `/api/logs?limit=50`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (status) url += `&filter_status=${encodeURIComponent(status)}`;

      const res = await fetch(url);
      if (handleAuthError(res) || !res.ok) return;
      const data = await res.json();
      const logs = data.logs || [];
      badgeLogCount.textContent = logs.length;

      if (logs.length === 0) {
        logsTableBody.innerHTML = `
          <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">
            Nenhuma consulta DNS registrada ainda.
          </td></tr>`;
        return;
      }

      logsTableBody.innerHTML = logs.map(item => {
        const isBlocked = item.status === "BLOCKED";
        const badgeClass = isBlocked ? "badge-blocked" : "badge-allowed";
        const statusLabel = isBlocked ? "BLOQUEADO" : "PERMITIDO";
        const quickActionBtn = isBlocked
          ? `<button class="btn btn-secondary btn-sm" onclick="window.quickUnblock('${escapeHtml(item.domain)}')">Desbloquear</button>`
          : `<button class="btn btn-danger btn-sm" onclick="window.quickBlockPrompt('${escapeHtml(item.domain)}')">Bloquear</button>`;

        return `
          <tr>
            <td class="font-mono" style="color:var(--text-secondary); font-size:0.78rem;">${escapeHtml(item.timestamp)}</td>
            <td class="font-mono">${escapeHtml(item.client_ip)}</td>
            <td class="font-mono" style="font-weight:500;">${escapeHtml(item.domain)}</td>
            <td class="font-mono" style="color:var(--text-muted);">${escapeHtml(item.query_type || "A")}</td>
            <td><span class="badge ${badgeClass}">${statusLabel}</span></td>
            <td>${quickActionBtn}</td>
          </tr>`;
      }).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // ==================== CLIENTS & WIREGUARD ====================
  async function loadClients() {
    try {
      const search = clientSearchInput.value.trim();
      let url = "/api/clients";
      if (search) url += `?search=${encodeURIComponent(search)}`;

      const res = await fetch(url);
      if (handleAuthError(res) || !res.ok) return;
      const data = await res.json();
      const clients = data.clients || [];
      badgeClientCount.textContent = clients.length;

      if (clients.length === 0) {
        clientsTableBody.innerHTML = `
          <tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">
            Nenhum cliente cadastrado. Clique em "Novo Cliente" para começar a vender planos.
          </td></tr>`;
        return;
      }

      clientsTableBody.innerHTML = clients.map(c => {
        let statusBadge = `<span class="badge badge-active">ATIVO</span>`;
        if (c.status === "SUSPENDED") statusBadge = `<span class="badge badge-suspended">SUSPENSO</span>`;
        if (c.status === "EXPIRED") statusBadge = `<span class="badge badge-expired">EXPIRADO</span>`;

        const toggleAction = c.status === "ACTIVE"
          ? `<button class="btn btn-secondary btn-sm" onclick="window.setClientStatus(${c.id}, 'SUSPENDED')">Suspender</button>`
          : `<button class="btn btn-primary btn-sm" onclick="window.setClientStatus(${c.id}, 'ACTIVE')">Ativar</button>`;

        return `
          <tr>
            <td>
              <div style="font-weight:600;">${escapeHtml(c.name)}</div>
              <div style="font-size:0.76rem; color:var(--text-secondary);" class="font-mono">${escapeHtml(c.username)} &bull; ${escapeHtml(c.email)}</div>
            </td>
            <td><span class="badge badge-category">${escapeHtml(c.plan_name || "Sem plano")}</span></td>
            <td class="font-mono">${c.device_count || 0} / ${c.max_devices || 2}</td>
            <td class="font-mono" style="font-size:0.8rem;">${escapeHtml((c.expires_at || "").slice(0, 10))}</td>
            <td>${statusBadge}</td>
            <td>
              <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
                <button class="btn btn-primary btn-sm" onclick="window.openClientDevices(${c.id}, '${escapeHtml(c.name)}')">📱 VPN / QR</button>
                <button class="btn btn-secondary btn-sm" onclick="window.renewClient(${c.id})">+30d</button>
                ${toggleAction}
                <button class="btn btn-danger btn-sm" onclick="window.deleteClient(${c.id})" title="Excluir cliente">🗑️</button>
              </div>
            </td>
          </tr>`;
      }).join("");
    } catch (err) {
      console.error(err);
    }
  }

  async function populatePlanSelect() {
    const res = await fetch("/api/plans");
    if (!res.ok) return;
    const data = await res.json();
    const plans = (data.plans || []).filter(p => p.is_active === 1);
    badgePlanCount.textContent = (data.plans || []).length;
    clientPlanSelect.innerHTML = plans.map(p =>
      `<option value="${p.id}">${escapeHtml(p.name)} — R$ ${Number(p.price).toFixed(2)} (${p.max_devices} disp.)</option>`
    ).join("");
  }

  btnOpenAddClientModal.addEventListener("click", async () => {
    addClientForm.reset();
    await populatePlanSelect();
    addClientModal.classList.add("active");
  });
  closeAddClientModal.addEventListener("click", () => addClientModal.classList.remove("active"));
  cancelAddClientBtn.addEventListener("click", () => addClientModal.classList.remove("active"));

  addClientForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(addClientForm);
    if (!fd.get("auto_create_device")) fd.set("auto_create_device", "0");
    const res = await fetch("/api/clients", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Erro ao criar cliente.", "error");
      return;
    }
    showToast("Cliente criado e túnel WireGuard provisionado!");
    addClientModal.classList.remove("active");
    loadClients();
    loadStats();
  });

  window.setClientStatus = async function(clientId, newStatus) {
    const fd = new FormData();
    fd.append("status", newStatus);
    const res = await fetch(`/api/clients/${clientId}/status`, { method: "POST", body: fd });
    if (res.ok) {
      showToast(`Cliente atualizado para ${newStatus}. WireGuard sincronizado.`);
      loadClients();
      loadStats();
    }
  };

  window.renewClient = async function(clientId) {
    const res = await fetch(`/api/clients/${clientId}/renew`, { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      showToast(`Assinatura renovada até ${data.expires_at.slice(0, 10)}!`);
      loadClients();
      loadStats();
    }
  };

  window.deleteClient = async function(clientId) {
    if (!confirm("Excluir este cliente e todos os seus dispositivos VPN?")) return;
    const res = await fetch(`/api/clients/${clientId}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Cliente removido.");
      loadClients();
      loadStats();
    }
  };

  window.openClientDevices = async function(clientId, clientName) {
    document.getElementById("devicesModalClientId").value = clientId;
    document.getElementById("clientDevicesTitle").textContent = `Dispositivos VPN — ${clientName}`;
    await refreshClientDevicesTable(clientId);
    clientDevicesModal.classList.add("active");
  };

  async function refreshClientDevicesTable(clientId) {
    const res = await fetch(`/api/clients/${clientId}/devices`);
    if (!res.ok) return;
    const data = await res.json();
    const devices = data.devices || [];

    if (devices.length === 0) {
      clientDevicesTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:1.5rem;">Nenhum dispositivo gerado.</td></tr>`;
      return;
    }

    clientDevicesTableBody.innerHTML = devices.map(d => `
      <tr>
        <td style="font-weight:600;">${escapeHtml(d.name)}</td>
        <td class="font-mono">${escapeHtml(d.vpn_ip)}</td>
        <td>
          <div style="display:flex; gap:0.4rem;">
            <button class="btn btn-primary btn-sm" onclick="window.viewDeviceQr(${d.id})">📱 QR Code</button>
            <a href="/api/devices/${d.id}/config" class="btn btn-secondary btn-sm">⬇️ .conf</a>
          </div>
        </td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="window.deleteDevice(${d.id}, ${clientId})">🗑️</button>
        </td>
      </tr>`).join("");
  }

  adminAddDeviceForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const clientId = document.getElementById("devicesModalClientId").value;
    const fd = new FormData(adminAddDeviceForm);
    const res = await fetch(`/api/clients/${clientId}/devices`, { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Erro ao gerar dispositivo.", "error");
      return;
    }
    adminAddDeviceForm.reset();
    showToast(`Dispositivo criado com IP ${data.vpn_ip}!`);
    await refreshClientDevicesTable(clientId);
    loadClients();
    loadStats();
  });

  window.viewDeviceQr = async function(deviceId) {
    const res = await fetch(`/api/devices/${deviceId}/qr`);
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById("qrViewerTitle").textContent = `${data.device.name} (${data.device.vpn_ip})`;
    document.getElementById("qrViewerSvg").innerHTML = data.qr_svg;
    document.getElementById("qrViewerText").value = data.config_text;
    document.getElementById("qrViewerDownload").href = `/api/devices/${deviceId}/config`;
    document.getElementById("qrViewerModal").classList.add("active");
  };

  window.deleteDevice = async function(deviceId, clientId) {
    if (!confirm("Revogar acesso deste dispositivo?")) return;
    const res = await fetch(`/api/devices/${deviceId}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Dispositivo revogado.");
      await refreshClientDevicesTable(clientId);
      loadClients();
      loadStats();
    }
  };

  // ==================== PLANS ====================
  async function loadPlans() {
    const res = await fetch("/api/plans");
    if (handleAuthError(res) || !res.ok) return;
    const data = await res.json();
    const plans = data.plans || [];
    badgePlanCount.textContent = plans.length;

    plansGrid.innerHTML = plans.map(p => `
      <div class="plan-card">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
            <h3 style="font-size:1.1rem; font-weight:600;">${escapeHtml(p.name)}</h3>
            <span class="badge ${p.is_active ? 'badge-active' : 'badge-suspended'}">${p.is_active ? 'ATIVO' : 'INATIVO'}</span>
          </div>
          <div class="plan-price">R$ ${Number(p.price).toFixed(2).replace(".", ",")} <span>/ ${p.duration_days} dias</span></div>
          <p style="font-size:0.84rem; color:var(--text-secondary); margin-top:0.6rem;">${escapeHtml(p.description || "Sem descrição")}</p>
        </div>
        <div style="border-top:1px solid var(--border-subtle); padding-top:0.85rem; display:flex; justify-content:space-between; align-items:center;">
          <span class="font-mono" style="font-size:0.8rem; color:var(--text-secondary);">Até ${p.max_devices} dispositivos</span>
          <div style="display:flex; gap:0.4rem;">
            <button class="btn btn-secondary btn-sm" onclick="window.togglePlan(${p.id})">${p.is_active ? 'Desativar' : 'Ativar'}</button>
            <button class="btn btn-danger btn-sm" onclick="window.deletePlan(${p.id})">🗑️</button>
          </div>
        </div>
      </div>`).join("");
  }

  btnOpenAddPlanModal.addEventListener("click", () => {
    addPlanForm.reset();
    addPlanModal.classList.add("active");
  });
  closeAddPlanModal.addEventListener("click", () => addPlanModal.classList.remove("active"));
  cancelAddPlanBtn.addEventListener("click", () => addPlanModal.classList.remove("active"));

  addPlanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(addPlanForm);
    const res = await fetch("/api/plans", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Erro ao criar plano.", "error");
      return;
    }
    showToast("Plano criado com sucesso!");
    addPlanModal.classList.remove("active");
    loadPlans();
  });

  window.togglePlan = async function(planId) {
    const res = await fetch(`/api/plans/${planId}/toggle`, { method: "POST" });
    if (res.ok) {
      showToast("Status do plano atualizado.");
      loadPlans();
    }
  };

  window.deletePlan = async function(planId) {
    if (!confirm("Remover este plano?")) return;
    const res = await fetch(`/api/plans/${planId}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Plano excluído.");
      loadPlans();
    }
  };

  // ==================== CATEGORIES & BLOCKED DOMAINS ====================
  async function loadCategories() {
    const res = await fetch("/api/categories");
    if (!res.ok) return;
    const data = await res.json();
    const cats = data.categories || [];
    categoriesGrid.innerHTML = cats.map(c => {
      const isOn = c.active_count > 0;
      return `
        <div class="category-pack">
          <div>
            <div style="font-weight:600; font-size:0.9rem;">${escapeHtml(c.category)}</div>
            <div style="font-size:0.76rem; color:var(--text-secondary);">${c.active_count} / ${c.total} ativos</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" ${isOn ? "checked" : ""} onchange="window.toggleCategory('${escapeHtml(c.category)}', this.checked)">
            <span class="toggle-slider"></span>
          </label>
        </div>`;
    }).join("");
  }

  window.toggleCategory = async function(category, checked) {
    const fd = new FormData();
    fd.append("category", category);
    fd.append("enable", checked ? "1" : "0");
    const res = await fetch("/api/categories/toggle", { method: "POST", body: fd });
    if (res.ok) {
      showToast(`Categoria "${category}" ${checked ? "ativada" : "pausada"}!`);
      loadCategories();
      loadBlockedDomains();
      loadStats();
    }
  };

  async function loadBlockedDomains() {
    try {
      const search = domainSearchInput.value.trim();
      let url = "/api/blocked-domains";
      if (search) url += `?search=${encodeURIComponent(search)}`;

      const res = await fetch(url);
      if (handleAuthError(res) || !res.ok) return;
      const data = await res.json();
      const domains = data.domains || [];
      badgeDomainCount.textContent = domains.length;

      if (domains.length === 0) {
        domainsTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:2rem;">Nenhum domínio cadastrado.</td></tr>`;
        return;
      }

      domainsTableBody.innerHTML = domains.map(d => `
        <tr>
          <td class="font-mono" style="font-weight:600;">${escapeHtml(d.domain)}</td>
          <td><span class="badge badge-category">${escapeHtml(d.category || "Geral")}</span></td>
          <td style="color:var(--text-secondary);">${escapeHtml(d.reason || "-")}</td>
          <td class="font-mono">${(d.hits || 0).toLocaleString()}</td>
          <td>
            <label class="toggle-switch">
              <input type="checkbox" ${d.enabled === 1 ? "checked" : ""} onchange="window.toggleDomain(${d.id})">
              <span class="toggle-slider"></span>
            </label>
          </td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="window.deleteDomain(${d.id})" title="Remover">🗑️</button>
          </td>
        </tr>`).join("");
    } catch (err) {
      console.error(err);
    }
  }

  async function loadUnblockRequests() {
    try {
      const res = await fetch("/api/unblock-requests");
      if (handleAuthError(res) || !res.ok) return;
      const data = await res.json();
      const reqs = data.requests || [];
      badgeRequestCount.textContent = reqs.length;

      if (reqs.length === 0) {
        requestsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:2rem;">Nenhuma solicitação pendente.</td></tr>`;
        return;
      }

      requestsTableBody.innerHTML = reqs.map(r => `
        <tr>
          <td class="font-mono" style="font-size:0.78rem; color:var(--text-secondary);">${escapeHtml(r.created_at)}</td>
          <td class="font-mono" style="font-weight:600; color:var(--accent-primary);">${escapeHtml(r.domain)}</td>
          <td class="font-mono">${escapeHtml(r.client_ip)}</td>
          <td>${escapeHtml(r.reason)}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="window.quickUnblock('${escapeHtml(r.domain)}')">✓ Liberar Acesso</button>
          </td>
        </tr>`).join("");
    } catch (err) {
      console.error(err);
    }
  }

  window.toggleDomain = async function(id) {
    const res = await fetch(`/api/blocked-domains/${id}/toggle`, { method: "POST" });
    if (res.ok) {
      showToast("Regra atualizada e DNS sincronizado!");
      loadCategories();
      loadStats();
    }
  };

  window.deleteDomain = async function(id) {
    if (!confirm("Remover este domínio da lista de bloqueio?")) return;
    const res = await fetch(`/api/blocked-domains/${id}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Domínio removido do bloqueio.");
      loadBlockedDomains();
      loadCategories();
      loadStats();
    }
  };

  window.quickBlockPrompt = function(domain) {
    document.getElementById("newDomainInput").value = domain;
    document.getElementById("newCategorySelect").value = "Geral";
    document.getElementById("newReasonInput").value = "Bloqueio solicitado via monitor de consultas";
    addDomainModal.classList.add("active");
  };

  window.quickUnblock = async function(domain) {
    const res = await fetch(`/api/blocked-domains?search=${encodeURIComponent(domain)}`);
    const data = await res.json();
    const match = (data.domains || []).find(d => d.domain.toLowerCase() === domain.toLowerCase());
    if (match) {
      await window.deleteDomain(match.id);
      loadQueryLogs();
    } else {
      showToast("O domínio já não consta na lista de bloqueios ativos.", "error");
    }
  };

  btnOpenAddModal.addEventListener("click", () => {
    addDomainForm.reset();
    addDomainModal.classList.add("active");
  });
  closeAddModal.addEventListener("click", () => addDomainModal.classList.remove("active"));
  cancelAddBtn.addEventListener("click", () => addDomainModal.classList.remove("active"));

  addDomainForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await fetch("/api/blocked-domains", { method: "POST", body: new FormData(addDomainForm) });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Erro ao adicionar domínio.", "error");
      return;
    }
    showToast(`Domínio ${data.domain} bloqueado e DNS atualizado!`);
    addDomainModal.classList.remove("active");
    loadBlockedDomains();
    loadCategories();
    loadStats();
  });

  btnOpenBulkModal.addEventListener("click", () => {
    bulkForm.reset();
    bulkModal.classList.add("active");
  });
  closeBulkModal.addEventListener("click", () => bulkModal.classList.remove("active"));
  cancelBulkBtn.addEventListener("click", () => bulkModal.classList.remove("active"));

  bulkForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await fetch("/api/blocked-domains/bulk", { method: "POST", body: new FormData(bulkForm) });
    const data = await res.json();
    if (res.ok) {
      showToast(`${data.added_count} de ${data.total_submitted} domínios importados!`);
      bulkModal.classList.remove("active");
      loadBlockedDomains();
      loadCategories();
      loadStats();
    }
  });

  // Settings & Password Forms
  settingsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(settingsForm);
    const res = await fetch("/api/settings", { method: "POST", body: fd });
    if (res.ok) {
      showToast("Configurações salvas e regras DNS recalculadas!");
      document.getElementById("headerServerIp").textContent = fd.get("server_ip");
    }
  });

  changePasswordForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await fetch("/api/auth/change-password", { method: "POST", body: new FormData(changePasswordForm) });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.detail || "Erro ao alterar senha.", "error");
      return;
    }
    changePasswordForm.reset();
    showToast("Senha administrativa alterada com sucesso!");
  });

  btnSyncDns.addEventListener("click", async () => {
    btnSyncDns.disabled = true;
    btnSyncDns.textContent = "Recarregando...";
    try {
      const res = await fetch("/api/sync-dns", { method: "POST" });
      const data = await res.json();
      if (data.success) showToast(`DNS atualizado: ${data.active_rules} regras ativas.`);
    } finally {
      btnSyncDns.disabled = false;
      btnSyncDns.innerHTML = "<span>🔄</span> Recarregar DNS";
    }
  });

  btnRefreshLogs.addEventListener("click", () => { loadQueryLogs(); loadStats(); });
  logSearchInput.addEventListener("input", debounce(loadQueryLogs, 300));
  logStatusFilter.addEventListener("change", loadQueryLogs);
  clientSearchInput.addEventListener("input", debounce(loadClients, 300));
  domainSearchInput.addEventListener("input", debounce(loadBlockedDomains, 300));
  btnRefreshRequests.addEventListener("click", loadUnblockRequests);

  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  function setupAutoRefresh() {
    if (autoRefreshCheckbox.checked) {
      autoRefreshTimer = setInterval(() => {
        if (activeTab === "tab-logs") {
          loadQueryLogs();
          loadStats();
        }
      }, 5000);
    } else if (autoRefreshTimer) {
      clearInterval(autoRefreshTimer);
    }
  }
  autoRefreshCheckbox.addEventListener("change", setupAutoRefresh);

  function updateLiveClock() {
    const clockEl = document.getElementById("liveClock");
    if (!clockEl) return;
    clockEl.textContent = new Intl.DateTimeFormat("pt-BR", {
      timeZone: "America/Sao_Paulo",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    }).format(new Date());
  }
  updateLiveClock();
  setInterval(updateLiveClock, 1000);

  // Initial Load
  loadStats();
  loadQueryLogs();
  populatePlanSelect();
  setupAutoRefresh();
});
