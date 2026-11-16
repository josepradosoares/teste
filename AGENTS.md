# NetShield DNS (DnsFamilia) — Regras do Projeto

Este arquivo é carregado automaticamente para qualquer tarefa neste repositório (inclusive quando executada via `/boost`).

## Stack e Estrutura
- **Backend Web (`web/`):** FastAPI + Uvicorn + Jinja2 + SQLite (`app.py`, `database.py`, `validators.py`, `dns_manager.py`, `wg_manager.py`).
- **Frontend (`web/templates/`, `web/static/`):** HTML (Jinja2), CSS puro (`style.css`, `blockpage.css`) e Vanilla JS (`app.js`).
- **Infraestrutura (`config/`, `scripts/`, `install.sh`, `update.sh`):** Nginx (reverse proxy + sinkhole), duas instâncias `dnsmasq` (porta 53 pago / 5354 Free), WireGuard (`wg0`) e `iptables`/`ip6tables`.
- **Testes (`tests/`):** `pytest` + `TestClient`.

## Uso Obrigatório das Skills do Superpowers (por contexto / arquivo)
Ao iniciar qualquer tarefa (normal ou `/boost`), leia e siga a skill correspondente antes de agir:

| Contexto / Arquivos | Skill a carregar |
|---|---|
| Nova feature, componente ou mudança de comportamento (`web/`, `config/`, `scripts/`) | `brainstorming` e `writing-plans` |
| Implementação ou alteração de código em `web/*.py` ou `tests/*.py` | `test-driven-development` |
| Investigação de erro, falha de teste, DNS, WireGuard ou firewall (`web/`, `update.sh`, `install.sh`) | `systematic-debugging` |
| Revisão de PR/código ou entrega de tarefa maior | `requesting-code-review` (ou `receiving-code-review` ao receber feedback) |
| Múltiplas tarefas independentes em paralelo | `dispatching-parallel-agents` |
| Antes de afirmar que qualquer correção ou feature está pronta | `verification-before-completion` |

> **Frontend (`web/templates/`, `web/static/`):** ao depurar layout, sessão/cookies ou acessibilidade com o servidor rodando, usar também `chrome-devtools`, `cookie-debugging` ou `a11y-debugging` conforme o caso.

## Padrões Obrigatórios do Código
1. **Validação e Segurança:**
   - Toda entrada de usuário (nomes, domínios, textos) deve passar por `web/validators.py` e ter `max_length` nos `Form(...)`.
   - Nunca inserir texto de usuário diretamente em `wg0.conf` ou arquivos de configuração do `dnsmasq`.
   - Usar `X-Real-IP` (não `X-Forwarded-For`) para IP do cliente; manter segredos fora de respostas da API.
2. **Backend e Concorrência:**
   - Rotas que acessam SQLite ou `subprocess` devem usar `def` síncrono (nunca `async def` bloqueando o event loop).
   - Operações em `wg0.conf`, `iptables` e arquivos do `dnsmasq` devem usar lock e escrita atômica.
3. **Frontend:**
   - Escapar todo dado dinâmico no JS com `escapeHtml()` ou `textContent` (evitar `innerHTML` com dados de usuário).

## Verificação Obrigatória Antes de Concluir
Sempre executar e confirmar saída sem erros após a última edição em Python:
```powershell
.venv\Scripts\python -m pytest tests -q
.venv\Scripts\python -m pyflakes web tests
```
