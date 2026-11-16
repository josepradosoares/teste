#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Script de Instalação Automatizada para Servidor Linux
# Compatibilidade: Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11 / 12
# ==============================================================================

set -e

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "=================================================================="
echo "    🛡️  INSTALADOR AUTOMATIZADO - NETSHIELD DNS & PAINEL WEB      "
echo "=================================================================="
echo -e "${NC}"

# 1. Verificar se está executando como root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Este script precisa ser executado como root ou com sudo!${NC}"
  echo "Exemplo: sudo bash install.sh"
  exit 1
fi

# 2. Detectar IP do servidor (Público para nuvem ou Local)
echo -e "${CYAN}[1/8] Detectando endereço IP do servidor...${NC}"

# Tentar obter o IP público primeiro (essencial para VPS na nuvem como Oracle Cloud, AWS, etc.)
PUBLIC_IP=$(curl -s --connect-timeout 3 https://api.ipify.org 2>/dev/null || curl -s --connect-timeout 3 https://ifconfig.me 2>/dev/null || echo "")

if [ -n "$PUBLIC_IP" ] && [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SERVER_IP="$PUBLIC_IP"
  echo -e "${GREEN}✓ IP Público detectado: ${SERVER_IP}${NC}"
else
  LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
  if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(hostname -I | awk '{print $1}')
  fi
  SERVER_IP="${LOCAL_IP:-152.67.44.54}"
  echo -e "${GREEN}✓ IP Local/Fallback detectado: ${SERVER_IP}${NC}"
fi

# 3. Atualizar repositórios e instalar pacotes essenciais
echo -e "\n${CYAN}[2/8] Instalando dependências (dnsmasq, nginx, python3, openssl)...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y dnsmasq nginx python3 python3-pip python3-venv openssl curl

# 4. Tratar conflito de porta 53 com systemd-resolved (comum no Ubuntu)
echo -e "\n${CYAN}[3/8] Configurando systemd-resolved para liberar a porta 53...${NC}"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  mkdir -p /etc/systemd/resolved.conf.d/
  cat << 'EOF' > /etc/systemd/resolved.conf.d/netshield-dns.conf
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved || true
fi

# 5. Criar diretórios de instalação do NetShield
echo -e "\n${CYAN}[4/8] Criando diretórios do sistema (/opt/netshield)...${NC}"
mkdir -p /opt/netshield/web
mkdir -p /opt/netshield/data
mkdir -p /opt/netshield/ssl
mkdir -p /etc/dnsmasq.d

# Copiar arquivos da aplicação web
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -r "${SCRIPT_DIR}/web/"* /opt/netshield/web/

# 6. Configurar ambiente virtual Python e dependências
echo -e "\n${CYAN}[5/8] Configurando ambiente Python (FastAPI / Uvicorn)...${NC}"
python3 -m venv /opt/netshield/venv
/opt/netshield/venv/bin/pip install --upgrade pip
/opt/netshield/venv/bin/pip install -r /opt/netshield/web/requirements.txt

# 7. Gerar Certificado SSL Autoassinado para a porta 443 do Nginx
echo -e "\n${CYAN}[6/8] Gerando certificado SSL de segurança para interceptação HTTPS...${NC}"
if [ ! -f /etc/netshield/ssl/cert.pem ]; then
  mkdir -p /etc/netshield/ssl
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/netshield/ssl/key.pem \
    -out /etc/netshield/ssl/cert.pem \
    -subj "/C=BR/ST=SP/L=Local/O=NetShield/OU=Security/CN=netshield.local" >/dev/null 2>&1
fi

# Configurar Nginx
echo -e "\n${CYAN}[7/8] Configurando Nginx e dnsmasq...${NC}"
cp "${SCRIPT_DIR}/config/nginx_blockpage.conf" /etc/nginx/sites-available/netshield.conf
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/netshield.conf /etc/nginx/sites-enabled/netshield.conf
nginx -t && systemctl restart nginx

# Configurar dnsmasq
cp "${SCRIPT_DIR}/config/dnsmasq.conf" /etc/dnsmasq.conf
touch /var/log/dnsmasq.log
chmod 644 /var/log/dnsmasq.log
touch /etc/dnsmasq.d/netshield_blocked.conf

# Inicializar o banco de dados com o IP correto do servidor
export NETSHIELD_DB_PATH=/opt/netshield/data/netshield.db
export NETSHIELD_DNSMASQ_CONF=/etc/dnsmasq.d/netshield_blocked.conf
export NETSHIELD_LOG_PATH=/var/log/dnsmasq.log

/opt/netshield/venv/bin/python -c "
import sys
sys.path.append('/opt/netshield/web')
import database as db
import dns_manager
db.init_db()
db.update_setting('server_ip', '${SERVER_IP}')
dns_manager.sync_dnsmasq_blocklist()
"

systemctl restart dnsmasq
systemctl enable dnsmasq

# 8. Liberar Firewall interno no Linux (Portas 80, 443 e 53)
echo -e "\n${CYAN}[8/9] Configurando regras de Firewall local (iptables)...${NC}"
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate DNAT -p udp --dport 5354 -j ACCEPT
iptables -I INPUT 1 -m conntrack --ctstate DNAT -p tcp --dport 5354 -j ACCEPT
# Tentar persistir regras se iptables-persistent estiver instalado
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi

NETSHIELD_DB_PATH=/opt/netshield/data/netshield.db /opt/netshield/venv/bin/python -c "import sys; sys.path.append('/opt/netshield/web'); import wg_manager; wg_manager.sync_router_dns_nat()" 2>/dev/null || true

# 9. Instalar e iniciar o serviço systemd
echo -e "\n${CYAN}[9/9] Criando e iniciando o serviço NetShield Web Panel...${NC}"
cp "${SCRIPT_DIR}/config/netshield.service" /etc/systemd/system/netshield.service
systemctl daemon-reload
systemctl enable netshield.service
systemctl restart netshield.service

echo -e "\n${GREEN}=================================================================="
echo "    🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO!                          "
echo "==================================================================${NC}"
echo -e "
${YELLOW}ACESSO AO PAINEL DE CONTROLE:${NC}
  👉 URL do Painel:  ${CYAN}http://${SERVER_IP}/admin${NC} (ou ${CYAN}http://${SERVER_IP}/?admin=1${NC})
  👉 IP do seu DNS:  ${CYAN}${SERVER_IP}${NC} (Porta 53 UDP/TCP)

${YELLOW}COMO USAR NO SEU COMPUTADOR OU ROTEADOR:${NC}
  1. Vá nas configurações de rede da sua máquina ou roteador.
  2. Altere o servidor ${GREEN}DNS Primário / Preferencial${NC} para: ${CYAN}${SERVER_IP}${NC}
  3. Ao acessar um site bloqueado (ex: tiktok.com, bet365.com), ele será
     redirecionado para a tela com o aviso e motivo configurado por você!

${YELLOW}COMANDOS ÚTEIS:${NC}
  • Ver status do painel:   sudo systemctl status netshield
  • Ver status do DNS:      sudo systemctl status dnsmasq
  • Ver logs de consultas:  sudo tail -f /var/log/dnsmasq.log
"
