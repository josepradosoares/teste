# 🛡️ NetShield DNS - Servidor DNS Privado com Painel de Controle e Página de Bloqueio

O **NetShield DNS** é uma solução completa para transformar qualquer servidor Linux (Ubuntu/Debian) em um **servidor DNS particular** com **DNS Sinkhole**, **monitoramento de consultas em tempo real** e uma **página personalizada de bloqueio** que explica ao usuário o motivo de um site ter sido restrito.

---

## 🚀 Principais Recursos

* **Servidor DNS Próprio (dnsmasq):**
  * Resolução ultrarrápida com cache local.
  * Encaminha requisições permitidas para servidores upstream seguros (Cloudflare `1.1.1.1` e Google `8.8.8.8`).
  * Intercepta domínios restritos e responde com o IP do seu servidor (Sinkhole).
* **Página de Bloqueio Informativa (HTML/CSS responsivo):**
  * Quando um usuário tenta acessar um domínio proibido, ele visualiza uma tela explicando exatamente o motivo da restrição (ex: *Redes Sociais*, *Apostas*, *Conteúdo Adulto* ou motivo customizado).
  * Exibe detalhes da conexão (IP do dispositivo, data/horário e e-mail do administrador).
  * Inclui botão para o usuário **Solicitar Desbloqueio** com justificativa, enviada diretamente ao painel do administrador.
* **Painel de Controle Web Administrativo (Python FastAPI + SQLite):**
  * **Monitor de Consultas em Tempo Real:** visualize quem acessou o quê, horários, status (PERMITIDO / BLOQUEADO) e filtros instantâneos.
  * **Bloqueio e Desbloqueio com 1 Clique:** adicione ou remova domínios diretamente pelo histórico de acessos.
  * **Importação em Massa:** cadastre centenas de domínios de uma só vez colando uma lista de texto.
  * **Sincronização Automática:** qualquer alteração no painel recarrega o DNS instantaneamente sem derrubar a rede.
  * **Design Moderno:** construído com Vanilla CSS refinado, paleta HSL e tipografia focada em produtividade.

---

## 🏗️ Arquitetura do Sistema

```
                      ┌──────────────────────────────┐
                      │    Dispositivo Cliente       │
                      │  (DNS = IP do seu Servidor)  │
                      └──────────────┬───────────────┘
                                     │
                     Consulta DNS    │
                     (Porta 53 UDP)  ▼
               ┌───────────────────────────────────────────┐
               │                 dnsmasq                   │
               │                                           │
               │ • Permitido: Consulta upstream (1.1.1.1)  │
               │ • Bloqueado: Responde com o IP do Servidor│
               │ • Grava logs em /var/log/dnsmasq.log      │
               └─────────────────────┬─────────────────────┘
                                     │
              Redirecionamento       │
              (HTTP Porta 80)        ▼
               ┌───────────────────────────────────────────┐
               │                  Nginx                    │
               │                                           │
               │  Recebe a requisição com o cabeçalho Host │
               │  e repassa para o NetShield Web           │
               └─────────────────────┬─────────────────────┘
                                     │
                                     ▼
               ┌───────────────────────────────────────────┐
               │         NetShield Web (FastAPI)           │
               │                                           │
               │  • /blocked: Página de aviso amigável     │
               │  • /admin: Painel de Controle completo    │
               │  • API REST: Estatísticas e gerenciamento │
               └───────────────────────────────────────────┘
```

---

## 📦 Como Instalar no Servidor Linux

### Pré-requisitos
* Sistema Operacional: **Ubuntu 20.04 / 22.04 / 24.04 LTS** ou **Debian 11 / 12**.
* Acesso como `root` ou usuário com privilégios `sudo`.
* Portas liberadas no firewall: `53` (UDP/TCP para DNS) e `80` (TCP para HTTP).

### Instalação em 1 Passo:
Conecte via SSH no seu servidor e execute:

```bash
git clone https://github.com/josepradosoares/teste.git netshield
cd netshield
sudo bash install.sh
```

O instalador automatizado cuidará de tudo:
1. Detecta o IP do servidor na rede.
2. Instala `dnsmasq`, `nginx`, `python3` e dependências.
3. Ajusta o `systemd-resolved` para liberar a porta 53 sem conflitos.
4. Gera certificados SSL autoassinados para conexões HTTPS.
5. Inicializa o banco de dados com regras de exemplo.
6. Cria e inicia o serviço systemd `netshield.service`.

---

## 🖥️ Como Acessar o Painel de Controle

Após a instalação, abra o navegador e acesse:

```
http://IP_DO_SEU_SERVIDOR/admin
```
*(ou `http://IP_DO_SEU_SERVIDOR/?admin=1`)*

No painel você poderá:
* Ver as estatísticas e gráficos de acessos.
* Adicionar novos domínios proibidos com seus respectivos motivos.
* Acompanhar as consultas DNS dos clientes em tempo real.
* Liberar ou aprovar solicitações de acesso.

---

## ⚙️ Como Configurar os Clientes para Usar o DNS

Para que o servidor filtre o tráfego dos dispositivos, aponte o **DNS Primário** para o **IP do seu Servidor Linux**:

### 1. No Roteador da Rede (Recomendado para toda a empresa ou casa)
1. Acesse o painel do seu roteador (ex: `192.168.1.1` ou `192.168.0.1`).
2. Vá em **Configurações DHCP / Rede Local (LAN)** (ou **WAN / Internet**).
3. No campo **DNS Primário (Primary DNS)**, digite o IP do servidor: `152.67.44.54` (deixe o DNS Secundário vazio ou `0.0.0.0`).
4. Salve e reinicie o roteador.
5. Para **Planos Pagos**, acesse o **Portal do Assinante** (`/cliente`) e clique em **Vincular Meu IP Atual** para que seu roteador receba a lista de bloqueio completa. IPs não vinculados recebem automaticamente o **Plano Free (Família & Cristão)**.

### 2. No Windows (Individual)
1. Abra **Configurações** &rarr; **Rede e Internet** &rarr; **Propriedades da Conexão**.
2. Em **Atribuição de Servidor DNS**, clique em **Editar** e selecione **Manual**.
3. Ative **IPv4** e em **DNS Preferencial**, informe o IP do servidor Linux.

### 3. No Linux (Individual)
Edite `/etc/resolv.conf`:
```bash
nameserver IP_DO_SEU_SERVIDOR
```

---

## 🛠️ Comandos de Gerenciamento do Servidor

```bash
# Verificar status dos serviços
sudo systemctl status netshield
sudo systemctl status dnsmasq
sudo systemctl status nginx

# Reiniciar o painel web
sudo systemctl restart netshield

# Ver consultas DNS em tempo real no terminal
sudo tail -f /var/log/dnsmasq.log
```

---

## 🔄 Como Atualizar no Servidor Linux

Conecte via SSH no servidor, entre na pasta do repositório e execute:

```bash
cd ~/netshield   # ou o caminho onde clonou o repositório
git pull origin main
sudo bash update.sh
```

---

## 🗑️ Como Desinstalar

Se desejar remover completamente o NetShield e restaurar as configurações originais do sistema:

```bash
sudo bash uninstall.sh
```

---

## 📄 Licença
Distribuído sob a licença GNU GPL v3.0. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.
