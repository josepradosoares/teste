#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Script de Diagnóstico e Correção Total do DNS
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}=== INICIANDO DIAGNÓSTICO E CORREÇÃO DO NETSHIELD DNS ===${NC}\n"

# 1. Liberar completamente todas as regras do iptables para a porta 53
echo -e "${YELLOW}[1/6] Configurando regras irrestritas no Firewall do Linux (iptables)...${NC}"
iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT

# 2. Desativar qualquer serviço que possa estar sequestrando a porta 53 (ex: systemd-resolved)
echo -e "${YELLOW}[2/6] Verificando e liberando conflito de porta 53 (systemd-resolved)...${NC}"
mkdir -p /etc/systemd/resolved.conf.d/
cat << 'EOF' > /etc/systemd/resolved.conf.d/netshield-dns.conf
[Resolve]
DNSStubListener=no
EOF
systemctl restart systemd-resolved || true

# 3. Configurar dnsmasq para escutar em 0.0.0.0 (todas as interfaces)
echo -e "${YELLOW}[3/6] Reescrevendo /etc/dnsmasq.conf com configurações ideais de rede...${NC}"
cat << 'EOF' > /etc/dnsmasq.conf
# NetShield DNS - Configuração de Produção
port=53
no-resolv
no-poll
server=1.1.1.1
server=8.8.8.8
cache-size=10000
domain-needed
bogus-priv
log-queries
log-facility=/var/log/dnsmasq.log
conf-file=/etc/dnsmasq.d/netshield_blocked.conf
EOF

# 4. Sincronizar domínios bloqueados e IP público
echo -e "${YELLOW}[4/6] Sincronizando blocklist e IP 152.67.44.54...${NC}"
mkdir -p /etc/dnsmasq.d
cat << 'EOF' > /etc/dnsmasq.d/netshield_blocked.conf
# NetShield DNS - Regras de Bloqueio
address=/tiktok.com/152.67.44.54
address=/www.tiktok.com/152.67.44.54
address=/bet365.com/152.67.44.54
address=/blaze.com/152.67.44.54
address=/xvideos.com/152.67.44.54
address=/pornhub.com/152.67.44.54
address=/torrentz2eu.org/152.67.44.54
EOF

# Atualizar banco
export NETSHIELD_DB_PATH=/opt/netshield/data/netshield.db
/opt/netshield/venv/bin/python -c "
import sys; sys.path.append('/opt/netshield/web')
import database as db, dns_manager
db.init_db()
db.update_setting('server_ip', '152.67.44.54')
dns_manager.sync_dnsmasq_blocklist()
" 2>/dev/null || true

# 5. Reiniciar o serviço dnsmasq
echo -e "${YELLOW}[5/6] Reiniciando serviço dnsmasq...${NC}"
systemctl restart dnsmasq
systemctl enable dnsmasq

# 6. Testes locais
echo -e "\n${CYAN}[6/6] Realizando testes de resolução DNS local...${NC}"
sleep 1

# Teste 1: Localhost
RES_LOCAL=$(nslookup tiktok.com 127.0.0.1 2>&1 || true)
echo "--------------------------------------------------------"
echo "Teste 1 (Localhost 127.0.0.1):"
echo "$RES_LOCAL"
echo "--------------------------------------------------------"

# Teste 2: Interface interna 10.0.0.43
RES_INT=$(nslookup tiktok.com 10.0.0.43 2>&1 || true)
echo "Teste 2 (Interface Interna 10.0.0.43):"
echo "$RES_INT"
echo "--------------------------------------------------------"

if echo "$RES_INT" | grep -q "152.67.44.54"; then
  echo -e "\n${GREEN}✓ SUCESSO: O SERVIDOR DNS ESTÁ RESPONDENDO PERFEITAMENTE NO LINUX!${NC}"
else
  echo -e "\n${RED}✗ Alerta: O dnsmasq não respondeu como esperado. Verifique o log: journalctl -u dnsmasq -n 20${NC}"
fi
