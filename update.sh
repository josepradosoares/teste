#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Script de Atualização e Auto-Reparo Definitivo (Oracle Cloud / VPS)
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=================================================================="
echo "    🛡️  NETSHIELD DNS - AUTO-ATUALIZAÇÃO & PERSISTÊNCIA TOTAL    "
echo "=================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Execute este script como root ou com sudo:${NC}"
  echo "sudo bash update.sh"
  exit 1
fi

echo -e "${CYAN}[1/7] Detectando IP Público do Servidor...${NC}"
SERVER_IP=$(curl -s --connect-timeout 4 https://api.ipify.org 2>/dev/null || curl -s --connect-timeout 4 https://ifconfig.me 2>/dev/null || echo "")
if [ -z "$SERVER_IP" ] || [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SERVER_IP=$(hostname -I | awk '{print $1}')
fi
if [ -z "$SERVER_IP" ] || [[ "$SERVER_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]; then
  SERVER_IP="152.67.44.54"
fi
echo -e "${GREEN}✓ IP do Servidor configurado: ${SERVER_IP}${NC}"

echo -e "\n${CYAN}[2/7] Atualizando arquivos da aplicação a partir do repositório...${NC}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /opt/netshield/web /opt/netshield/data /opt/netshield/ssl /etc/dnsmasq.d /var/www/certbot
cp -r "${REPO_DIR}/web/"* /opt/netshield/web/
/opt/netshield/venv/bin/pip install -q -r /opt/netshield/web/requirements.txt
cp "${REPO_DIR}/config/nginx_blockpage.conf" /etc/nginx/sites-available/netshield.conf
ln -sf /etc/nginx/sites-available/netshield.conf /etc/nginx/sites-enabled/netshield.conf
rm -f /etc/nginx/sites-enabled/default

echo -e "\n${CYAN}[3/7] Configurando dnsmasq para responder requisições externas...${NC}"
cat << 'EOF' > /etc/dnsmasq.conf
# NetShield DNS - Configuração de Alta Disponibilidade e Baixa Latência
port=53
no-resolv
no-poll
all-servers
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
cache-size=10000
min-cache-ttl=300
dns-forward-max=1024
domain-needed
bogus-priv
log-queries
log-facility=/var/log/dnsmasq.log
conf-file=/etc/dnsmasq.d/netshield_blocked.conf

# Permitir respostas a qualquer interface (incluindo wg0 10.8.0.1)
bind-dynamic
EOF

# Instância dedicada do dnsmasq para o Plano Free Família & Cristão (porta 5354)
cat << 'EOF' > /etc/dnsmasq-free.conf
# NetShield DNS - Instância Plano Free (Família & Cristão)
port=5354
bind-dynamic
no-resolv
no-poll
all-servers
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
cache-size=5000
min-cache-ttl=300
dns-forward-max=512
domain-needed
bogus-priv
log-queries
log-facility=/var/log/dnsmasq.log
conf-file=/etc/dnsmasq.d/netshield_free_blocked.conf
EOF

cat << 'EOF' > /etc/systemd/system/netshield-dns-free.service
[Unit]
Description=NetShield DNS Free Tier (Familia & Cristao)
After=network.target dnsmasq.service

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq -k --conf-file=/etc/dnsmasq-free.conf --pid-file=/run/dnsmasq-free.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Desativar stub listener do systemd-resolved para evitar colisão na porta 53
mkdir -p /etc/systemd/resolved.conf.d/
cat << 'EOF' > /etc/systemd/resolved.conf.d/netshield-dns.conf
[Resolve]
DNSStubListener=no
EOF
systemctl restart systemd-resolved 2>/dev/null || true

echo -e "\n${CYAN}[4/7] Sincronizando banco de dados e regras de bloqueio...${NC}"
export NETSHIELD_DB_PATH=/opt/netshield/data/netshield.db
export NETSHIELD_DNSMASQ_CONF=/etc/dnsmasq.d/netshield_blocked.conf
export NETSHIELD_DNSMASQ_FREE_CONF=/etc/dnsmasq.d/netshield_free_blocked.conf
export NETSHIELD_LOG_PATH=/var/log/dnsmasq.log

/opt/netshield/venv/bin/python -c "
import sys; sys.path.append('/opt/netshield/web')
import database as db, dns_manager
db.init_db()
db.update_setting('server_ip', '${SERVER_IP}')
dns_manager.sync_dnsmasq_blocklist()
"

echo -e "\n${CYAN}[5/7] Configurando Firewall Permanente (Sobrevive a qualquer Reboot)...${NC}"
# 1. Aplicar imediatamente no iptables
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 53 -m hashlimit --hashlimit-above 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-name netshield_dns_rl -j DROP 2>/dev/null || true
iptables -I INPUT 2 -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate DNAT -p udp --dport 5354 -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate DNAT -p tcp --dport 5354 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT

# 2. Instalar e habilitar o serviço systemd de persistência do firewall
cat << 'EOF' > /etc/systemd/system/netshield-firewall.service
[Unit]
Description=NetShield Permanent Firewall Rules for Oracle Cloud
DefaultDependencies=no
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
ExecStart=/bin/sh -c '/sbin/iptables -I INPUT 1 -p udp --dport 53 -m hashlimit --hashlimit-above 200/sec --hashlimit-burst 400 --hashlimit-mode srcip --hashlimit-name netshield_dns_rl -j DROP 2>/dev/null || true'
ExecStart=/sbin/iptables -I INPUT 2 -p udp --dport 53 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT 1 -m conntrack --ctstate DNAT -p udp --dport 5354 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT 1 -m conntrack --ctstate DNAT -p tcp --dport 5354 -j ACCEPT
ExecStart=/sbin/iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF

systemctl daemon-reload
systemctl enable netshield-firewall.service
systemctl restart netshield-firewall.service

# Instalar também iptables-persistent se disponível
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent netfilter-persistent 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

echo -e "\n${CYAN}[5/7] Configurando Fuso Horário (São Paulo - Brasil)...${NC}"
timedatectl set-timezone America/Sao_Paulo || true
echo -e "${GREEN}✓ Fuso horário configurado para $(timedatectl | grep "Time zone" || date)${NC}"

echo -e "\n${CYAN}[5.5/7] Otimizando Kernel & Rede (Google BBR + Streaming 4K) e Logrotate...${NC}"
bash "${REPO_DIR}/scripts/optimize_network.sh"

cat << 'EOF' > /etc/logrotate.d/netshield-dnsmasq
/var/log/dnsmasq.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

echo -e "\n${CYAN}[6/7] Habilitando e iniciando todos os serviços essenciais...${NC}"
cp "${REPO_DIR}/config/netshield.service" /etc/systemd/system/netshield.service
systemctl daemon-reload
systemctl enable netshield.service dnsmasq netshield-dns-free.service nginx
systemctl restart dnsmasq
systemctl restart netshield-dns-free.service
systemctl restart netshield.service
systemctl restart nginx
NETSHIELD_DB_PATH=/opt/netshield/data/netshield.db /opt/netshield/venv/bin/python -c "import sys; sys.path.append('/opt/netshield/web'); import wg_manager; wg_manager.sync_wireguard_peers()" 2>/dev/null || true

# Aguardar 2 segundos para o FastAPI iniciar na porta 8080
sleep 2

echo -e "\n${CYAN}[7/7] Executando testes automatizados do sistema...${NC}"
# Teste HTTP
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/admin || echo "000")
# Teste DNS
DNS_TEST=$(nslookup tiktok.com 127.0.0.1 2>/dev/null | grep -c "${SERVER_IP}" || echo "0")

echo -e "\n${GREEN}=================================================================="
echo "    🎉 NETSHIELD DNS ATUALIZADO E TOTALMENTE PROTEGIDO!           "
echo "==================================================================${NC}"
echo -e "
${YELLOW}RESULTADO DOS TESTES:${NC}
  • Painel Web Local:  $([ "$HTTP_CODE" = "200" ] && echo -e "${GREEN}✓ ONLINE (HTTP 200)${NC}" || echo -e "${YELLOW}Status: $HTTP_CODE${NC}")
  • Resolução de DNS:  $([ "$DNS_TEST" -ge 1 ] && echo -e "${GREEN}✓ FUNCIONANDO (Responde ${SERVER_IP})${NC}" || echo -e "${RED}✗ Falha${NC}")
  • Firewall no Boot:  ${GREEN}✓ ATIVADO (Regras salvas permanentemente no Systemd)${NC}

${YELLOW}ACESSO AO SEU PAINEL:${NC}
  👉 URL:  ${CYAN}http://${SERVER_IP}/admin${NC}
  👉 DNS:  ${CYAN}${SERVER_IP}${NC} (Porta 53)
"
