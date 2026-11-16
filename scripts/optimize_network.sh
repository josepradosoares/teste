#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS & VPN - Otimização de Rede de Alta Velocidade (BBR + Streaming)
# ==============================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo "Execute como root: sudo bash scripts/optimize_network.sh"
  exit 1
fi

echo -e "${CYAN}[NetShield Turbo] Aplicando otimizações de Kernel (Google BBR + Buffers Streaming)...${NC}"

# Garantir módulos BBR e conntrack carregados quando disponíveis
modprobe tcp_bbr 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true

mkdir -p /etc/sysctl.d
cat << 'EOF' > /etc/sysctl.d/99-netshield-performance.conf
# NetShield DNS & WireGuard VPN - Tuning para Web Rápida e Streaming 4K
net.ipv4.ip_forward = 1

# Google BBR + Fair Queue (mantém bitrate alto e reduz bufferbloat)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Buffers TCP/UDP para alta vazão (Streaming e downloads)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 16384

# Baixa latência e estabilidade em links PPPoE / 4G / 5G / Fibra
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
EOF

# Adicionar nf_conntrack_max apenas se o parâmetro existir no kernel
if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
  echo "net.netfilter.nf_conntrack_max = 262144" >> /etc/sysctl.d/99-netshield-performance.conf
fi

sysctl -p /etc/sysctl.d/99-netshield-performance.conf >/dev/null 2>&1 || true

# Configurar rotação de logs do dnsmasq para evitar lentidão de disco
cat << 'EOF' > /etc/logrotate.d/netshield-dnsmasq
/var/log/dnsmasq.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    maxsize 50M
}
EOF

CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "desconhecido")
echo -e "${GREEN}✓ Controle de Congestionamento ativo: ${CURRENT_CC}${NC}"
echo -e "${GREEN}✓ Rotação automática de logs (/var/log/dnsmasq.log) configurada${NC}"
