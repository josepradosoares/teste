#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Ativador de DNS Privado Android (DoT - DNS over TLS Porta 853)
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DOMAIN="${1:-dnsjp.duckdns.org}"

echo -e "${BLUE}"
echo "=================================================================="
echo "    🔒 ATIVADOR DE DNS PRIVADO ANDROID (DoT - PORTA 853 TLS)      "
echo "=================================================================="
echo -e "${NC}"
echo -e "${CYAN}Domínio configurado: ${GREEN}${DOMAIN}${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Execute como root: sudo bash scripts/enable_dot.sh ${DOMAIN}${NC}"
  exit 1
fi

# 1. Instalar Certbot e Nginx Stream com SSL
echo -e "${CYAN}[1/5] Instalando Certbot e módulos de segurança...${NC}"
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y certbot libnginx-mod-stream

# 2. Obter Certificado SSL Let's Encrypt Oficial
echo -e "\n${CYAN}[2/5] Gerando Certificado SSL Let's Encrypt para ${DOMAIN}...${NC}"
# Pausa rápida no Nginx se estiver na porta 80 para validação standalone, ou usa webroot
if certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "${DOMAIN}" --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"; then
  echo -e "${GREEN}✓ Certificado SSL gerado com sucesso para ${DOMAIN}!${NC}"
  CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
else
  echo -e "${YELLOW}Aviso: Não foi possível gerar SSL Let's Encrypt standalone. Usando certificado existente ou autoassinado.${NC}"
  CERT_PATH="/etc/netshield/ssl/cert.pem"
  KEY_PATH="/etc/netshield/ssl/key.pem"
fi

# 3. Configurar Nginx Stream para DoT (Porta 853 TLS -> dnsmasq porta 53)
echo -e "\n${CYAN}[3/5] Configurando terminação TLS na porta 853 (DNS over TLS)...${NC}"
mkdir -p /etc/nginx/modules-enabled

cat << EOF > /etc/nginx/modules-enabled/50-mod-stream.conf
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
EOF

cat << EOF > /etc/nginx/conf.d/dot_stream.conf
# Proxy DNS over TLS (Porta 853) para dnsmasq (127.0.0.1:53)
stream {
    upstream dns_servers {
        server 127.0.0.1:53;
    }

    server {
        listen 853 ssl;
        ssl_certificate ${CERT_PATH};
        ssl_certificate_key ${KEY_PATH};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_session_cache shared:SSL:20m;
        ssl_session_timeout 4h;

        proxy_pass dns_servers;
        proxy_timeout 3s;
        proxy_responses 1;
    }
}
EOF

# Incluir stream no /etc/nginx/nginx.conf caso não esteja incluído
if ! grep -q "include /etc/nginx/conf.d/dot_stream.conf;" /etc/nginx/nginx.conf; then
  echo "include /etc/nginx/conf.d/dot_stream.conf;" >> /etc/nginx/nginx.conf
fi

# 4. Liberar porta 853 no Firewall iptables
echo -e "\n${CYAN}[4/5] Liberando porta 853 no firewall do Linux...${NC}"
iptables -I INPUT 1 -p tcp --dport 853 -j ACCEPT

# Adicionar porta 853 ao serviço de persistência
if [ -f /etc/systemd/system/netshield-firewall.service ]; then
  if ! grep -q "\-\-dport 853" /etc/systemd/system/netshield-firewall.service; then
    sed -i '/ExecStart=.*dport 53/a ExecStart=/sbin/iptables -I INPUT 1 -p tcp --dport 853 -j ACCEPT' /etc/systemd/system/netshield-firewall.service
    systemctl daemon-reload
    systemctl restart netshield-firewall.service
  fi
fi

# 5. Reiniciar serviços
echo -e "\n${CYAN}[5/5] Reiniciando Nginx e dnsmasq...${NC}"
nginx -t && systemctl restart nginx
systemctl restart dnsmasq

echo -e "\n${GREEN}=================================================================="
echo "    🎉 DNS PRIVADO ANDROID (DoT) ATIVADO COM SUCESSO!            "
echo "==================================================================${NC}"
echo -e "
${YELLOW}COMO USAR NO SEU CELULAR SAMSUNG / ANDROID:${NC}
  1. No seu celular, vá em:
     ${CYAN}Configurações &rarr; Conexões &rarr; Mais configurações de conexão &rarr; DNS Privado${NC}
  2. Selecione a opção:
     ${GREEN}Nome do host do provedor de DNS privado${NC}
  3. Digite:
     👉 ${CYAN}${DOMAIN}${NC}
  4. Toque em ${GREEN}Salvar${NC}.

${YELLOW}IMPORTANTE NA ORACLE CLOUD:${NC}
  Certifique-se de liberar a porta ${CYAN}853 TCP${NC} na Lista de Segurança da Oracle Cloud
  (exatamente como você liberou a porta 80 e 53)!
"
