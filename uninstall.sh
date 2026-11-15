#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS - Script de Desinstalação
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Execute como root: sudo bash uninstall.sh"
  exit 1
fi

echo "Desinstalando NetShield DNS..."

# Parar e desativar serviços
systemctl stop netshield 2>/dev/null || true
systemctl disable netshield 2>/dev/null || true
rm -f /etc/systemd/system/netshield.service
systemctl daemon-reload

# Restaurar Nginx
rm -f /etc/nginx/sites-enabled/netshield.conf
rm -f /etc/nginx/sites-available/netshield.conf
systemctl restart nginx 2>/dev/null || true

# Restaurar dnsmasq
rm -f /etc/dnsmasq.d/netshield_blocked.conf
systemctl restart dnsmasq 2>/dev/null || true

# Remover diretório de instalação
rm -rf /opt/netshield
rm -rf /etc/netshield

echo "NetShield DNS foi desinstalado com sucesso."
