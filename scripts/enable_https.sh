#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Ativador de HTTPS Oficial (Let's Encrypt / Certbot)
# Uso: sudo bash scripts/enable_https.sh dnsjp.duckdns.org [seu@email.com]
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DOMAIN="${1:-dnsjp.duckdns.org}"
EMAIL="${2:-}"

echo -e "${BLUE}"
echo "=================================================================="
echo "    🔒 NETSHIELD DNS - ATIVADOR DE HTTPS (LET'S ENCRYPT SSL)      "
echo "=================================================================="
echo -e "${NC}"
echo -e "${CYAN}Domínio alvo: ${GREEN}${DOMAIN}${NC}\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Execute como root: sudo bash scripts/enable_https.sh ${DOMAIN}${NC}"
  exit 1
fi

# 1. Instalar Certbot
echo -e "${CYAN}[1/5] Instalando Certbot...${NC}"
DEBIAN_FRONTEND=noninteractive apt-get update -y -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot

# 2. Garantir diretório webroot e firewall
echo -e "\n${CYAN}[2/5] Preparando diretório ACME e portas 80/443 no firewall...${NC}"
mkdir -p /var/www/certbot
iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT

# Garantir que nginx está com a config mais recente do repositório caso exista
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "${REPO_DIR}/config/nginx_blockpage.conf" ]; then
  cp "${REPO_DIR}/config/nginx_blockpage.conf" /etc/nginx/sites-available/netshield.conf
  ln -sf /etc/nginx/sites-available/netshield.conf /etc/nginx/sites-enabled/netshield.conf
  nginx -t && systemctl reload nginx
fi

# 3. Emitir Certificado Let's Encrypt
echo -e "\n${CYAN}[3/5] Solicitando certificado SSL oficial para ${DOMAIN}...${NC}"
if [ -n "$EMAIL" ]; then
  EMAIL_ARG="--email ${EMAIL}"
else
  EMAIL_ARG="--register-unsafely-without-email"
fi

if ! certbot certonly \
  --webroot -w /var/www/certbot \
  --non-interactive --agree-tos ${EMAIL_ARG} \
  --keep-until-expiring \
  -d "${DOMAIN}"; then
  echo -e "${YELLOW}Tentativa via webroot falhou. Tentando modo standalone (pausa breve no Nginx)...${NC}"
  certbot certonly \
    --standalone \
    --non-interactive --agree-tos ${EMAIL_ARG} \
    --keep-until-expiring \
    --pre-hook "systemctl stop nginx" \
    --post-hook "systemctl start nginx" \
    -d "${DOMAIN}"
fi

CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"

if [ ! -f "${CERT_PATH}" ] || [ ! -f "${KEY_PATH}" ]; then
  echo -e "${RED}[ERRO] Certificado não encontrado em ${CERT_PATH}. Verifique se o domínio ${DOMAIN} aponta para o IP público deste servidor e se a porta 80 está aberta na Oracle Cloud.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ Certificado SSL válido emitido com sucesso!${NC}"

# 4. Criar VirtualHost dedicado para o domínio do painel (não sobrescrito pelo update.sh)
echo -e "\n${CYAN}[4/5] Configurando Nginx HTTPS para ${DOMAIN}...${NC}"
cat << EOF > /etc/nginx/sites-available/netshield-https.conf
# ==============================================================================
# NetShield DNS - VirtualHost HTTPS Oficial (${DOMAIN})
# Gerado por scripts/enable_https.sh (preservado entre atualizações)
# ==============================================================================

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/certbot;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/netshield-https.conf /etc/nginx/sites-enabled/netshield-https.conf

# Configurar hook de renovação automática para recarregar o Nginx
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat << 'EOF' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
#!/bin/sh
systemctl reload nginx
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# 5. Validar e recarregar Nginx
echo -e "\n${CYAN}[5/5] Validando configuração e recarregando Nginx...${NC}"
nginx -t && systemctl reload nginx

HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://${DOMAIN}/login" || echo "000")

echo -e "\n${GREEN}=================================================================="
echo "    🎉 HTTPS ATIVADO COM SUCESSO PARA ${DOMAIN}!                  "
echo "==================================================================${NC}"
echo -e "
  • Acesso Seguro:  ${CYAN}https://${DOMAIN}${NC}
  • Teste HTTPS:    $([ "$HTTPS_CODE" = "200" ] && echo -e "${GREEN}✓ ONLINE (HTTP 200)${NC}" || echo -e "${YELLOW}Status: $HTTPS_CODE${NC}")
  • Renovação:      ${GREEN}✓ Automática via systemd timer do Certbot${NC}

${YELLOW}DICA:${NC}
  As páginas de bloqueio DNS continuam funcionando normalmente no servidor padrão,
  enquanto o seu Painel Admin e o Portal do Cliente agora usam cadeado verde HTTPS!
"
