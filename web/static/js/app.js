// NetShield DNS - Client-side Application Logic
document.addEventListener("DOMContentLoaded", () => {
  // State
  let autoRefreshTimer = null;
  let activeTab = "tab-logs";

  // Elements
  const tabs = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const toastContainer = document.getElementById("toastContainer");

  // Metrics Elements
  const statTotalQueries = document.getElementById("statTotalQueries");
  const statTotalBlocked = document.getElementById("statTotalBlocked");
  const statBlockRate = document.getElementById("statBlockRate");
  const statActiveRules = document.getElementById("statActiveRules");
  const badgeLogCount = document.getElementById("badgeLogCount");
  const badgeDomainCount = document.getElementById("badgeDomainCount");
  const badgeRequestCount = document.getElementById("badgeRequestCount");

  // Tab 1 Elements (Logs)
  const logsTableBody = document.getElementById("logsTableBody");
  const logSearchInput = document.getElementById("logSearchInput");
  const logStatusFilter = document.getElementById("logStatusFilter");
  const btnRefreshLogs = document.getElementById("btnRefreshLogs");
  const autoRefreshCheckbox = document.getElementById("autoRefreshCheckbox");

  // Tab 2 Elements (Domains)
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

  // Tab 3 Elements (Requests)
  const requestsTableBody = document.getElementById("requestsTableBody");
  const btnRefreshRequests = document.getElementById("btnRefreshRequests");

  // Tab 4 Elements (Settings)
  const settingsForm = document.getElementById("settingsForm");
  const btnSyncDns = document.getElementById("btnSyncDns");

  // Toast Function
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
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
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

      // Load specific tab data on switch
      if (activeTab === "tab-domains") loadBlockedDomains();
      if (activeTab === "tab-requests") loadUnblockRequests();
      if (activeTab === "tab-logs") loadQueryLogs();
    });
  });

  // Fetch KPI Stats
  async function loadStats() {
    try {
      const res = await fetch("/api/stats");
      if (!res.ok) return;
      const data = await res.json();
      statTotalQueries.textContent = (data.total_queries || 0).toLocaleString();
      statTotalBlocked.textContent = (data.total_blocked || 0).toLocaleString();
      statBlockRate.textContent = `${data.block_rate || 0}%`;
      statActiveRules.textContent = (data.active_blocked_domains || 0).toLocaleString();
      badgeDomainCount.textContent = data.active_blocked_domains || 0;
    } catch (e) {
      console.error("Error loading stats:", e);
    }
  }

  // Load Query Logs
  async function loadQueryLogs() {
    try {
      const search = logSearchInput.value.trim();
      const status = logStatusFilter.value;
      let url = `/api/logs?limit=50`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (status) url += `&filter_status=${encodeURIComponent(status)}`;

      const res = await fetch(url);
      if (!res.ok) throw new Error("Erro ao carregar logs");
      const data = await res.json();
      const logs = data.logs || [];
      badgeLogCount.textContent = logs.length;

      if (logs.length === 0) {
        logsTableBody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
              Nenhuma consulta DNS encontrada com os filtros atuais.
            </td>
          </tr>
        `;
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
            <td class="font-mono" style="color: var(--text-secondary); font-size: 0.78rem;">${escapeHtml(item.timestamp)}</td>
            <td class="font-mono">${escapeHtml(item.client_ip)}</td>
            <td class="font-mono" style="font-weight: 500;">${escapeHtml(item.domain)}</td>
            <td class="font-mono" style="color: var(--text-muted);">${escapeHtml(item.query_type || "A")}</td>
            <td><span class="badge ${badgeClass}">${statusLabel}</span></td>
            <td>${quickActionBtn}</td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Load Blocked Domains
  async function loadBlockedDomains() {
    try {
      const search = domainSearchInput.value.trim();
      let url = "/api/blocked-domains";
      if (search) url += `?search=${encodeURIComponent(search)}`;

      const res = await fetch(url);
      if (!res.ok) throw new Error("Erro ao carregar domínios");
      const data = await res.json();
      const domains = data.domains || [];
      badgeDomainCount.textContent = domains.length;

      if (domains.length === 0) {
        domainsTableBody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
              Nenhum domínio bloqueado cadastrado. Clique em "Novo Bloqueio" para adicionar.
            </td>
          </tr>
        `;
        return;
      }

      domainsTableBody.innerHTML = domains.map(d => {
        const isChecked = d.enabled === 1 ? "checked" : "";
        return `
          <tr>
            <td class="font-mono" style="font-weight: 600;">${escapeHtml(d.domain)}</td>
            <td><span class="badge badge-category">${escapeHtml(d.category || "Geral")}</span></td>
            <td style="color: var(--text-secondary);">${escapeHtml(d.reason || "-")}</td>
            <td class="font-mono">${(d.hits || 0).toLocaleString()}</td>
            <td>
              <label class="toggle-switch">
                <input type="checkbox" ${isChecked} onchange="window.toggleDomain(${d.id})">
                <span class="toggle-slider"></span>
              </label>
            </td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="window.deleteDomain(${d.id})" title="Remover da lista">
                🗑️
              </button>
            </td>
          </tr>
        `;
      }).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Load Unblock Requests
  async function loadUnblockRequests() {
    try {
      const res = await fetch("/api/unblock-requests");
      if (!res.ok) return;
      const data = await res.json();
      const reqs = data.requests || [];
      badgeRequestCount.textContent = reqs.length;

      if (reqs.length === 0) {
        requestsTableBody.innerHTML = `
          <tr>
            <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
              Nenhuma solicitação de desbloqueio pendente.
            </td>
          </tr>
        `;
        return;
      }

      requestsTableBody.innerHTML = reqs.map(r => `
        <tr>
          <td class="font-mono" style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(r.created_at)}</td>
          <td class="font-mono" style="font-weight: 600; color: var(--accent-primary);">${escapeHtml(r.domain)}</td>
          <td class="font-mono">${escapeHtml(r.client_ip)}</td>
          <td>${escapeHtml(r.reason)}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="window.quickUnblock('${escapeHtml(r.domain)}')">
              ✓ Liberar Acesso
            </button>
          </td>
        </tr>
      `).join("");
    } catch (err) {
      console.error(err);
    }
  }

  // Global helper actions
  window.toggleDomain = async function(id) {
    try {
      const res = await fetch(`/api/blocked-domains/${id}/toggle`, { method: "POST" });
      const data = await res.json();
      if (data.success) {
        showToast("Regra atualizada e DNS sincronizado!");
        loadStats();
      }
    } catch (e) {
      showToast("Falha ao alternar status do domínio.", "error");
    }
  };

  window.deleteDomain = async function(id) {
    if (!confirm("Tem certeza que deseja remover este domínio da lista de bloqueio?")) return;
    try {
      const res = await fetch(`/api/blocked-domains/${id}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        showToast("Domínio removido do bloqueio.");
        loadBlockedDomains();
        loadStats();
      }
    } catch (e) {
      showToast("Erro ao excluir domínio.", "error");
    }
  };

  window.quickBlockPrompt = function(domain) {
    document.getElementById("newDomainInput").value = domain;
    document.getElementById("newCategorySelect").value = "Geral";
    document.getElementById("newReasonInput").value = "Bloqueio solicitado via monitor de consultas";
    addDomainModal.classList.add("active");
  };

  window.quickUnblock = async function(domain) {
    // Find domain id from list
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

  // Add Domain Modal Events
  btnOpenAddModal.addEventListener("click", () => {
    addDomainForm.reset();
    addDomainModal.classList.add("active");
  });
  closeAddModal.addEventListener("click", () => addDomainModal.classList.remove("active"));
  cancelAddBtn.addEventListener("click", () => addDomainModal.classList.remove("active"));

  addDomainForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(addDomainForm);
    try {
      const res = await fetch("/api/blocked-domains", { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.detail || "Erro ao adicionar domínio.", "error");
        return;
      }
      showToast(`Domínio ${data.domain} adicionado e DNS atualizado!`);
      addDomainModal.classList.remove("active");
      loadBlockedDomains();
      loadStats();
    } catch (err) {
      showToast("Erro de comunicação com o servidor.", "error");
    }
  });

  // Bulk Import Modal Events
  btnOpenBulkModal.addEventListener("click", () => {
    bulkForm.reset();
    bulkModal.classList.add("active");
  });
  closeBulkModal.addEventListener("click", () => bulkModal.classList.remove("active"));
  cancelBulkBtn.addEventListener("click", () => bulkModal.classList.remove("active"));

  bulkForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(bulkForm);
    try {
      const res = await fetch("/api/blocked-domains/bulk", { method: "POST", body: formData });
      const data = await res.json();
      if (data.success) {
        showToast(`${data.added_count} de ${data.total_submitted} domínios importados com sucesso!`);
        bulkModal.classList.remove("active");
        loadBlockedDomains();
        loadStats();
      }
    } catch (err) {
      showToast("Erro na importação em massa.", "error");
    }
  });

  // Settings Form Submit
  settingsForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(settingsForm);
    try {
      const res = await fetch("/api/settings", { method: "POST", body: formData });
      const data = await res.json();
      if (data.success) {
        showToast("Configurações salvas e regras DNS recalculadas!");
        document.getElementById("headerServerIp").textContent = formData.get("server_ip");
      }
    } catch (err) {
      showToast("Erro ao salvar configurações.", "error");
    }
  });

  // Force Sync DNS Button
  btnSyncDns.addEventListener("click", async () => {
    btnSyncDns.disabled = true;
    btnSyncDns.textContent = "Recarregando...";
    try {
      const res = await fetch("/api/sync-dns", { method: "POST" });
      const data = await res.json();
      if (data.success) {
        showToast(`DNS atualizado: ${data.active_rules} regras ativas aplicadas.`);
      } else {
        showToast("DNS atualizado localmente.", "success");
      }
    } catch (e) {
      showToast("Falha ao recarregar serviço DNS.", "error");
    } finally {
      btnSyncDns.disabled = false;
      btnSyncDns.innerHTML = "<span>🔄</span> Recarregar DNS";
    }
  });

  // Filter and Search Events
  btnRefreshLogs.addEventListener("click", () => {
    loadQueryLogs();
    loadStats();
  });
  logSearchInput.addEventListener("input", debounce(loadQueryLogs, 300));
  logStatusFilter.addEventListener("change", loadQueryLogs);
  domainSearchInput.addEventListener("input", debounce(loadBlockedDomains, 300));
  btnRefreshRequests.addEventListener("click", loadUnblockRequests);

  // Debounce helper
  function debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }

  // Auto Refresh Interval
  function setupAutoRefresh() {
    if (autoRefreshCheckbox.checked) {
      autoRefreshTimer = setInterval(() => {
        if (activeTab === "tab-logs") {
          loadQueryLogs();
          loadStats();
        }
      }, 5000);
    } else {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    }
  }

  autoRefreshCheckbox.addEventListener("change", setupAutoRefresh);

  // Initial Load
  loadStats();
  loadQueryLogs();
  setupAutoRefresh();
});
