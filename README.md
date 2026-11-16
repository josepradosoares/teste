# 🛡️ NetShield DNS - Servidor DNS Privado, WireGuard VPN e Painel Multi-Planos

O **NetShield DNS** é uma solução completa para transformar um servidor Linux (Ubuntu/Debian) em um **servidor DNS privado com filtragem por planos**, **WireGuard VPN dual-stack (IPv4 + IPv6)**, **configuração direta no roteador (`152.67.44.54`)**, **monitoramento de consultas em tempo real** e **página personalizada de bloqueio**.

---

## 📦 Estrutura de Planos

| Plano | Preço | Dispositivos VPN | Roteador (`152.67.44.54`) | Filtros e Modo WireGuard |
| :--- | :--- | :--- | :--- | :--- |
| **Plano Free (Família & Cristão)** | **R$ 0,00** | 1 dispositivo | Padrão automático (sem vínculo) | Adulto, Apostas, Malware + SafeSearch. WireGuard em **Split-Tunnel (`dns_only`)**. |
| **Plano Completo** | **R$ 15,00 / mês** | Até 5 dispositivos | Vínculo de IP no Portal (`/cliente`) | Tudo do Free + Anúncios & Trackers, Redes Sociais e P2P/Jogos. WireGuard em **VPN Criptografada (`full`, saída com IP da VPS)** por padrão, com opção de alternar para `dns_only` por dispositivo. |

---

## 🚀 Principais Recursos Implementados

* **Duas Instâncias DNS (`dnsmasq`) com Roteamento por Plano:**
  * `dnsmasq` (Porta `53`): lista completa para **Planos Pagos / Completo**.
  * `netshield-dns-free` (Porta `5354`): lista do **Plano Free Família & Cristão** + SafeSearch (Google, Bing e YouTube).
  * Roteamento automático via `iptables` / `ip6tables` (`NETSHIELD_DNS_FREE` para VPN e `NETSHIELD_ROUTER_DNS` para roteadores externos).
* **WireGuard VPN Dual-Stack (IPv4 + IPv6):**
  * Sub-rede IPv4 `10.8.0.0/24` e IPv6 ULA `fd10:8::/64` com `MASQUERADE` (NAT/NAT66).
  * Geração automática de `.conf` e **QR Code** no Portal do Assinante (`/cliente`).
  * No **Plano Completo**, os dispositivos usam **VPN Criptografada (IP de saída da VPS)** por padrão, podendo alternar individualmente para **Só DNS (`dns_only`)** para streaming 4K direto.
* **Portal do Assinante (`/cliente`) com Guia de Roteador:**
  * Seção dedicada explicando passo a passo como configurar o roteador com o DNS `152.67.44.54`.
  * Botão **Vincular Meu IP Atual** (ou edição manual) para liberar o **Plano Completo** direto na rede Wi-Fi de casa/empresa.
* **Painel Administrativo (Python FastAPI + SQLite):**
  * **Monitor de Consultas em Tempo Real:** status (`PERMITIDO` / `BLOQUEADO`), filtros e limpeza automática de `query_logs` antigos (`> 7 dias`).
  * **Modo de Bloqueio Configurável (`block_mode`):** alterne entre **`sinkhole`** (redireciona para a página de bloqueio em HTTP) e **`null` (`0.0.0.0`)** (bloqueio silencioso sem aviso de certificado em HTTPS).
  * **Importação em Massa e Sincronização Imediata:** atualiza as listas e recarrega os serviços `dnsmasq` sem derrubar a rede.
* **Hardening e Otimização de Rede (Linux):**
  * Rate-limit na porta `53` UDP (`hashlimit`) contra abuso de Open Resolver.
  * Rotação diária de logs (`/etc/logrotate.d/netshield-dnsmasq`) e tuning de kernel (`BBR` + `fq` + buffers TCP/UDP + forwarding IPv4/IPv6).

---

## 🏗️ Arquitetura do Sistema

```
                ┌──────────────────────────────────────────┐
                │   Dispositivos / Roteadores / WireGuard  │
                │  • Roteador WAN -> 152.67.44.54:53       │
                │  • WireGuard    -> 10.8.0.1 / fd10:8::1  │
                └────────────────────┬─────────────────────┘
                                     │
                 iptables / ip6tables NAT (por plano)
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
     ┌───────────────────────────────┐ ┌───────────────────────────────┐
     │     dnsmasq (Porta 53)        │ │ netshield-dns-free (5354)     │
     │  • Plano Completo (Pago)      │ │ • Plano Free Família & Cristão│
     └───────────────┬───────────────┘ └───────────────┬───────────────┘
                     └───────────────┬───────────────┘
                                     │ (Modo sinkhole -> HTTP/HTTPS)
                                     ▼
                ┌──────────────────────────────────────────┐
                │      Nginx (80/443) -> FastAPI (8080)    │
                │  • /blocked  • /cliente  • /admin  • API │
                └──────────────────────────────────────────┘
```

---

## 📦 Como Instalar no Servidor Linux

### Pré-requisitos
* **Ubuntu 20.04 / 22.04 / 24.04 LTS** ou **Debian 11 / 12** com acesso `root`/`sudo`.
* Portas liberadas no firewall da nuvem (ex.: Oracle Cloud Security List):
  * `53` (UDP/TCP — DNS)
  * `80` e `443` (TCP — Painel Web e Página de Bloqueio)
  * `51820` (UDP — WireGuard VPN)

### Instalação
```bash
git clone https://github.com/josepradosoares/teste.git netshield
cd netshield
sudo bash install.sh
```

---

## 🖥️ Acessos
* **Painel Administrativo:** `http://152.67.44.54/admin`
* **Portal do Assinante / Cadastro Free:** `http://152.67.44.54/login` e `http://152.67.44.54/cliente`

---

## ⚙️ Como Configurar no Roteador (`152.67.44.54`)

1. Acesse o painel do seu roteador (ex: `192.168.1.1` ou `192.168.0.1`).
2. Vá em **Configurações DHCP / Rede Local (LAN)** (ou **WAN / Internet**).
3. No campo **DNS Primário**, informe `152.67.44.54` (deixe o **DNS Secundário** vazio ou `0.0.0.0`).
4. Salve e reinicie o roteador.
5. Para **Plano Completo (R$ 15/mês)**, acesse `/cliente` e clique em **Vincular Meu IP Atual** para aplicar os filtros completos na sua rede. IPs não vinculados recebem automaticamente o **Plano Free**.

---

## 🛠️ Comandos de Gerenciamento do Servidor

```bash
# Verificar status dos serviços
sudo systemctl status netshield dnsmasq netshield-dns-free nginx wg-quick@wg0

# Ver regras NAT do roteamento por plano
sudo iptables -t nat -L NETSHIELD_ROUTER_DNS -n -v
sudo iptables -t nat -L NETSHIELD_DNS_FREE -n -v

# Ver consultas DNS em tempo real
sudo tail -f /var/log/dnsmasq.log
```

---

## 🔄 Como Atualizar no Servidor Linux

Conecte via SSH no servidor, entre na pasta do repositório e execute:

```bash
cd ~/netshield && git pull origin main && sudo bash update.sh
```

*(Caso tenha acabado de aplicar a atualização com suporte IPv6 no WireGuard, reinicie uma vez a interface: `sudo systemctl restart wg-quick@wg0`.)*

---

## 🔐 Segurança

* **Senha Inicial do Admin:** Na primeira instalação (`install.sh`), uma senha aleatória é gerada automaticamente e exibida **uma única vez** no resumo final (também salva em `/opt/netshield/data/admin_initial_password.txt` com permissão `600` quando gerada pelo `init_db` sem `NETSHIELD_ADMIN_PASSWORD`). Instalações antigas que ainda usem `admin123` são obrigadas a trocar a senha ao acessar o painel.
* **Proteção contra Força Bruta e Abuso:**
  * Login limitado a **5 tentativas/minuto por IP** (e bloqueio de 15 minutos após 10 falhas por usuário).
  * Cadastro Free limitado a **3 contas/hora por IP** e solicitações de desbloqueio a **5/hora por IP** (além de `limit_req` no Nginx).
  * Porta `53` endurecida contra amplificação de DNS (bloqueio de consultas `ANY` e `hashlimit` de `30/s` com burst `60` por IP de origem).
* **Troca de Senha e Sessões:** Alterar a senha invalida automaticamente todas as sessões anteriores (`session_version`).

---

## 🗑️ Como Desinstalar

```bash
sudo bash uninstall.sh
```

---

## 📄 Licença
Distribuído sob a licença GNU GPL v3.0. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.
