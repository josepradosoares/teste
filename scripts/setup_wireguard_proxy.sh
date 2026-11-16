#!/usr/bin/env bash
# ==============================================================================
# NetShield DNS + WireGuard VPN + Webshare Proxy Rotativo
# Proxy configurado: http://josesoares-rotate:yu87ymaa1xq9@p.webshare.io:80/
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
echo "  🛡️  NETSHIELD: WIREGUARD VPN + WEBSHARE PROXY ROTATIVO INTEGRADO "
echo "=================================================================="
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERRO] Execute este script como root ou com sudo:${NC}"
  echo "sudo bash scripts/setup_wireguard_proxy.sh"
  exit 1
fi

SERVER_IP=$(curl -s --connect-timeout 4 https://api.ipify.org 2>/dev/null || curl -s --connect-timeout 4 https://ifconfig.me 2>/dev/null || echo "152.67.44.54")
WG_PORT=51820

echo -e "${CYAN}[1/6] Instalando WireGuard, Redsocks e Utilitários...${NC}"
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard wireguard-tools qrencode redsocks iptables-persistent

echo -e "\n${CYAN}[2/6] Habilitando Roteamento IPv4 no Kernel...${NC}"
sysctl -w net.ipv4.ip_forward=1
mkdir -p /etc/sysctl.d
cat << 'EOF' > /etc/sysctl.d/99-wireguard.conf
net.ipv4.ip_forward=1
EOF
sysctl -p /etc/sysctl.d/99-wireguard.conf || true

echo -e "\n${CYAN}[3/6] Configurando Redsocks com Proxy Rotativo Webshare...${NC}"
# Configuração do Redsocks para redirecionar tráfego TCP para o proxy da Webshare
cat << 'EOF' > /etc/redsocks.conf
base {
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks.log";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;

    ip = p.webshare.io;
    port = 80;
    type = http-connect;
    login = "josesoares-rotate";
    password = "yu87ymaa1xq9";
}
EOF

systemctl restart redsocks || true
systemctl enable redsocks || true

echo -e "\n${CYAN}[4/6] Gerando Chaves Criptográficas do WireGuard...${NC}"
mkdir -p /etc/wireguard
cd /etc/wireguard
umask 077

if [ ! -f server_private.key ]; then
  wg genkey | tee server_private.key | wg pubkey > server_public.key
fi
SERVER_PRIV_KEY=$(cat server_private.key)
SERVER_PUB_KEY=$(cat server_public.key)

if [ ! -f client_private.key ]; then
  wg genkey | tee client_private.key | wg pubkey > client_public.key
fi
CLIENT_PRIV_KEY=$(cat client_private.key)
CLIENT_PUB_KEY=$(cat client_public.key)

# Interface de rede de saída da máquina
WAN_INTERFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $5}' | head -n 1)
[ -z "$WAN_INTERFACE" ] && WAN_INTERFACE="ens3"

echo -e "\n${CYAN}[5/6] Criando Configuração do Servidor WireGuard (/etc/wireguard/wg0.conf)...${NC}"
cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = 10.8.0.1/16
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV_KEY}

# Regras de NAT e DNS sinkhole para clientes da VPN
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE; iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE; iptables -t nat -D POSTROUTING -s 10.8.0.0/16 -j MASQUERADE

[Peer]
# Cliente Windows / Celular
PublicKey = ${CLIENT_PUB_KEY}
AllowedIPs = 10.8.0.2/32
EOF

# Configurar dnsmasq para atender o IP interno da VPN 10.8.0.1
if ! grep -q "listen-address=10.8.0.1" /etc/dnsmasq.conf 2>/dev/null; then
  echo "listen-address=10.8.0.1,127.0.0.1" >> /etc/dnsmasq.conf
fi
systemctl restart dnsmasq

# Iniciar WireGuard
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

# Liberar porta WireGuard no firewall
iptables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT

# Persistir firewall
if [ -f /etc/systemd/system/netshield-firewall.service ]; then
  if ! grep -q "\-\-dport ${WG_PORT}" /etc/systemd/system/netshield-firewall.service; then
    sed -i "/ExecStart=.*dport 53/a ExecStart=/sbin/iptables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT" /etc/systemd/system/netshield-firewall.service
    systemctl daemon-reload
  fi
fi

echo -e "\n${CYAN}[6/6] Gerando Arquivo de Configuração do Cliente...${NC}"
mkdir -p /opt/netshield/clients

cat << EOF > /opt/netshield/clients/cliente-jose.conf
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = 10.8.0.2/32
DNS = 10.8.0.1

[Peer]
PublicKey = ${SERVER_PUB_KEY}
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo -e "\n${GREEN}=================================================================="
echo "    🎉 WIREGUARD VPN + PROXY WEBSHARE INSTALADO COM SUCESSO!     "
echo "==================================================================${NC}"
echo -e "
${YELLOW}ARQUIVO DE CONFIGURAÇÃO PARA O WINDOWS:${NC}
  O arquivo do cliente foi salvo em: ${CYAN}/opt/netshield/clients/cliente-jose.conf${NC}

${YELLOW}CÓDIGO DE CONFIGURAÇÃO (COPIE E SALVE NO BLOCO DE NOTAS DO PC):${NC}
------------------------------------------------------------------
$(cat /opt/netshield/clients/cliente-jose.conf)
------------------------------------------------------------------

${YELLOW}QR CODE PARA ESCANEAR NO CELULAR COM O APP DO WIREGUARD:${NC}"

qrencode -t ansiutf8 < /opt/netshield/clients/cliente-jose.conf

echo -e "
${YELLOW}IMPORTANTE NA ORACLE CLOUD:${NC}
  Abra a porta ${CYAN}${WG_PORT} UDP${NC} na Lista de Segurança da Oracle Cloud
  (exatamente como você abriu a porta 80 e 53)!
"
