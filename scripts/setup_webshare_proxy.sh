#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Servidor Proxy HTTP/HTTPS com Webshare Rotativo
# Proxy Upstream: http://josesoares-rotate:yu87ymaa1xq9@p.webshare.io:80/
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROXY_PORT=3128

echo -e "${BLUE}"
echo "=================================================================="
echo "    🛡️  NETSHIELD: SERVIDOR PROXY COM WEBSHARE ROTATIVO         "
echo "=================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Execute como root: sudo bash scripts/setup_webshare_proxy.sh${NC}"
  exit 1
fi

SERVER_IP=$(curl -s --connect-timeout 4 https://api.ipify.org 2>/dev/null || echo "152.67.44.54")

echo -e "${CYAN}[1/4] Instalando Squid Proxy Server...${NC}"
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y squid

echo -e "\n${CYAN}[2/4] Configurando Squid para integrar com Webshare e NetShield...${NC}"
cat << 'EOF' > /etc/squid/squid.conf
# NetShield DNS + Webshare Proxy Integrado
http_port 3128

# Encaminhar todo o tráfego permitido para o Proxy Rotativo Webshare
cache_peer p.webshare.io parent 80 0 no-query no-digest default login=josesoares-rotate:yu87ymaa1xq9

# Usar o servidor DNS local do NetShield para filtrar domínios proibidos
dns_nameservers 127.0.0.1

# Liberar acesso para navegação
acl all_clients src all
http_access allow all_clients

# Desabilitar cache local para garantir rotação contínua de IPs
cache deny all
forwarded_for off
via off
EOF

echo -e "\n${CYAN}[3/4] Liberando porta ${PROXY_PORT} no Firewall do Linux...${NC}"
iptables -I INPUT 1 -p tcp --dport ${PROXY_PORT} -j ACCEPT

# Persistir regra no systemd
if [ -f /etc/systemd/system/netshield-firewall.service ]; then
  if ! grep -q "\-\-dport ${PROXY_PORT}" /etc/systemd/system/netshield-firewall.service; then
    sed -i "/ExecStart=.*dport 53/a ExecStart=/sbin/iptables -I INPUT 1 -p tcp --dport ${PROXY_PORT} -j ACCEPT" /etc/systemd/system/netshield-firewall.service
    systemctl daemon-reload
    systemctl restart netshield-firewall.service
  fi
fi

echo -e "\n${CYAN}[4/4] Reiniciando serviço Squid Proxy...${NC}"
systemctl enable squid
systemctl restart squid

echo -e "\n${GREEN}=================================================================="
echo "    🎉 PROXY WEBSHARE CONFIGURADO COM SUCESSO NO SERVIDOR!        "
echo "==================================================================${NC}"
echo -e "
${YELLOW}DADOS DO SEU NOVO PROXY PARA COLOCAR NO WINDOWS OU CELULAR:${NC}
  👉 Endereço (IP ou Domínio): ${CYAN}${SERVER_IP}${NC} (ou ${CYAN}dnsjp.duckdns.org${NC})
  👉 Porta:                    ${GREEN}${PROXY_PORT}${NC}
  👉 Usuário e Senha:          ${YELLOW}Não precisa! (Já autenticado no servidor)${NC}

${YELLOW}COMO COLOCAR NO WINDOWS (SEM INSTALAR NADA):${NC}
  1. Abra as ${CYAN}Configurações do Windows &rarr; Rede e Internet &rarr; Proxy${NC}.
  2. Em \"Configuração manual de proxy\", ative ${GREEN}\"Usar um servidor proxy\"${NC}.
  3. Preencha:
     • Endereço: ${CYAN}${SERVER_IP}${NC}
     • Porta:    ${GREEN}${PROXY_PORT}${NC}
  4. Clique em Salvar. Pronto!

${YELLOW}COMO COLOCAR NO CELULAR SAMSUNG (SEM INSTALAR NADA):${NC}
  1. Vá em ${CYAN}Configurações &rarr; Conexões &rarr; Wi-Fi${NC} &rarr; engrenagem do seu Wi-Fi.
  2. Toque em ${CYAN}Ver mais &rarr; Proxy &rarr; Manual${NC}.
  3. Nome do host do proxy: ${CYAN}${SERVER_IP}${NC}
  4. Porta do proxy:        ${GREEN}${PROXY_PORT}${NC}
  5. Salvar.

${YELLOW}IMPORTANTE NA ORACLE CLOUD:${NC}
  Lembre-se de liberar a porta ${CYAN}${PROXY_PORT} TCP${NC} na Lista de Segurança da Oracle Cloud!
"
