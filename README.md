# tools.shiftsad.dev

Site estático com três ferramentas para administradores de servidores Minecraft + um backend Flask que serve a página estática e roda o VirusParcial.

## Páginas

- **Extrator de dependências** (`/dependency-extractor.html`) — totalmente client-side. Lê `plugin.yml` dentro de `.jar`/`.zip` com JSZip+js-yaml, mostra quem depende de qual plugin separando `depend` de `softdepend`.
- **FailMark** (`/failmark.html`) — totalmente client-side. Compara um CPU contra uma base curada com pontuações single-thread tipo PassMark, ordenando piores/mais antigos primeiro.
- **VirusParcial** (`/virus-parcial.html`) — usa a API. Aceita qualquer `.jar` (plugin Bukkit/Paper, mod Forge, mod Fabric). Hash local primeiro, upload só se necessário, três blocklists.
- **Admin** (`/admin.html`) — login com senha + dashboard pra gerenciar reports e blocklists.

## Como o VirusParcial decide se um .jar é vírus

O backend tem três blocklists + uma allowlist:

1. **Allowlist (`allowed_hashes`)** — tem precedência sobre tudo. Hash explicitamente permitido pelo admin → resposta imediata `clean`, sem analisar, sem armazenar, sem criar report.
2. **Hash sha256** — match exato no arquivo inteiro. Rigoroso, mas frágil (uma mudança trivial e o hash some).
3. **Package signature** — listas como `me.monkey` ou `me.monkey.*` casam contra o package layout do `.jar` (que é a árvore de diretórios dentro do zip — não precisa decompilar nada). Resistente a recompilação.
4. **URL/string** — substring (case-insensitive) contra qualquer URL `http(s)://...` encontrada nos `.class` e em recursos texto (`plugin.yml`, `MANIFEST.MF`, etc.). Pega C2 hardcoded e domínios de payload.

Quando nada bate, o arquivo é salvo no volume com nome `{sha256}.jar` (dedup automático), o report fica como "limpo" no admin, e você revisa manualmente.

A resposta pública nunca expõe qual lista bateu nem o pattern — só status, hash, tamanho, e (opcionalmente) um `label` que você definir.

### Auto-cache: package/URL match também adiciona o hash

Quando um match acontece por package ou URL (que precisam do arquivo inteiro pra ser detectados), o hash do arquivo é automaticamente inserido na blocklist de hashes com `source=auto:package:<pattern>` ou `auto:url:<pattern>`. Resultado: o **próximo** scan do mesmo .jar bate por hash via `/api/scan/check` — zero upload.

Se você deletar a regra que causou o auto-add, os hashes auto-adicionados por aquela regra também são removidos. Hashes adicionados manualmente nunca são tocados pelo cleanup.

### Status do report é computado ao vivo

Reports **não armazenam** "este é vírus" — armazenam só o hash + a análise (packages, URLs encontradas) + um snapshot de match no momento do scan (pra histórico).

A cada vez que o admin abre um report ou grupo, o backend re-executa o match contra as blocklists **atuais**. Isso significa: se você adiciona um pattern, todos os reports passados que batem com ele aparecem como infectados na hora. Se você remove o pattern (por falso positivo), todos os reports que dependiam dele voltam a aparecer como limpos — sem nenhuma migração ou cleanup manual.

"Marcar como vírus" no admin = só insere o hash na blocklist. Nada extra é guardado no report.

## Economia de banda — fluxo de 2 etapas

Railway cobra por GB de tráfego, então o cliente é otimizado pra mandar o mínimo possível:

1. **Hash local primeiro** — o browser calcula sha-256 do .jar via `crypto.subtle.digest`.
2. **Cache de sessão** — se o mesmo hash já foi consultado na sessão, mostra o resultado em cache, zero rede.
3. **`POST /api/scan/check {hash}`** — ~70B de payload. Backend checa só a blocklist de hashes. Se já bate, devolve "infected" e o cliente para aí — **não faz upload**.
4. **`POST /api/scan` (multipart)** — só se o hash for desconhecido. Aí sim a análise completa (packages + URLs) roda e o arquivo é armazenado pra revisão se ninguém marcar.

Rate limits (por IP):
- `/api/scan/check`: 120/hora (super leve)
- `/api/scan`: 8/hora, 30/dia (caro — controla o upload)
- `/api/admin/login`: 8/minuto (anti-bruteforce)

## Setup local

```bash
# 1) deps
python -m venv .venv
.venv\Scripts\activate           # Windows
# source .venv/bin/activate      # macOS/Linux
pip install -r requirements.txt

# 2) gera senha do admin
python scripts/hash_password.py "sua-senha"
# copia o output ($2b$...)

# 3) copia .env.example pra .env e preenche
copy .env.example .env           # Windows
# cp .env.example .env           # macOS/Linux

# edite .env e ponha:
#   SESSION_SECRET=<saída de:  python -c "import secrets; print(secrets.token_hex(32))">
#   ADMIN_PASSWORD_HASH=<saída do hash_password.py>

# 4) sobe
python wsgi.py
# abre http://localhost:3000/dependency-extractor.html
# admin em http://localhost:3000/admin.html
```

## Deploy no Railway

1. **Crie o projeto** apontando pro repositório do GitHub. Railway detecta Python via `requirements.txt` e Nixpacks.
2. **Adicione um volume** (Project → Settings → Volumes):
   - Mount path: `/data`
   - Tamanho: 1 GB já é mais que suficiente
3. **Variáveis de ambiente** (Project → Variables):
   - `DATA_DIR=/data`
   - `SESSION_SECRET=` (qualquer string aleatória ≥ 32 chars — gere com `python -c "import secrets; print(secrets.token_hex(32))"`)
   - `ADMIN_PASSWORD_HASH=` (rode `python scripts/hash_password.py "sua-senha"` localmente e cole aqui)
   - `MAX_UPLOAD_BYTES=52428800` (opcional, default 50MB)
4. **Domínio**: Settings → Networking → Generate Domain (ou Custom Domain pra `tools.shiftsad.dev`).

O start command já está no `railway.json`:
```
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60
```

`Procfile` também presente como fallback.

## API

### Pública

`POST /api/scan/check` — JSON `{hash}`. Retorna `{status: "infected"|"clean"|"unknown", label?}`. Sem upload. `clean` = está na allowlist; `unknown` = sobe o arquivo via `/api/scan`.

`POST /api/scan` — multipart com `file` (`.jar`, max 50MB) e `email` (opcional). Retorna:
```json
{ "status": "clean" | "infected",
  "hash": "<sha256>", "filename": "...", "size": 12345,
  "label": null | "label-publico" }
```

### Admin (requer `Authorization: Bearer <jwt>`)

- `POST /api/admin/login` — `{password}` → `{token}`
- `GET  /api/admin/summary` — contagens agregadas (computado ao vivo)
- `GET  /api/admin/reports/groups` — reports agrupados por hash, com `current_match` (live) e `at_scan_match` (snapshot histórico)
- `GET  /api/admin/reports?hash=&limit=` — lista bruta
- `GET  /api/admin/reports/{id}` — detalhe (inclui packages e URLs encontradas)
- `GET  /api/admin/reports/{id}/file` — baixa o `.jar`
- `POST /api/admin/groups/{hash}/mark-virus` — adiciona o hash à blocklist. Idempotente.
- `DELETE /api/admin/groups/{hash}` — apaga todos os reports daquele hash + o `.jar` no disco
- `GET|POST /api/admin/hashes` — `POST {hash, label?, source?}`
- `DELETE /api/admin/hashes/{hash}`
- `GET|POST /api/admin/packages` — `POST {pattern, label?}` (`me.monkey` ou `me.monkey.*`)
- `DELETE /api/admin/packages/{pattern}`
- `GET|POST /api/admin/urls` — `POST {pattern, label?}` (substring match)
- `DELETE /api/admin/urls/{pattern}`
- `GET|POST /api/admin/allowed` — allowlist de hashes confiáveis. `POST {hash, label?, source?}`
- `DELETE /api/admin/allowed/{hash}`
- `POST /api/admin/groups/{hash}/mark-clean` — adiciona o hash à allowlist (e remove da blocklist se estava lá)

Sessão dura 12h.

## Layout

```
tools/
├── wsgi.py                 # entry pro gunicorn / dev
├── app/
│   ├── __init__.py         # factory + static file serving
│   ├── config.py
│   ├── db.py               # SQLite + schema
│   ├── auth.py             # bcrypt + JWT
│   ├── analysis.py         # JAR walk + match
│   ├── scan.py             # POST /api/scan
│   └── admin.py            # /api/admin/*
├── public/                 # site estático (servido pelo Flask)
│   ├── index.html
│   ├── dependency-extractor.html
│   ├── failmark.html
│   ├── virus-parcial.html
│   ├── admin.html
│   ├── admin.js
│   ├── header.js
│   └── shared.css
├── scripts/
│   └── hash_password.py
├── requirements.txt
├── Procfile
├── railway.json
└── .env.example
```

## Notas

- **E-mail de notificação** — o sistema só armazena o e-mail no report; o envio é manual. A ideia é você abrir o admin, ver o veredicto, e mandar o e-mail você mesmo (assim você não precisa configurar SMTP/SES).
- **Dedup** — arquivos com mesmo hash não são salvos duas vezes; reports apontam pro mesmo arquivo.
- **Privacidade da blocklist** — usuários nunca vêem qual lista (hash/pkg/url) bateu nem o pattern específico, só status + label público.
- **Roadmap natural** — quando quiser ir além: YARA via `yara-python`, fuzzy hashing (ssdeep/tlsh), entropy analysis pra detectar packing, ML em cima das features extraídas. Tudo encaixa no `app/analysis.py` sem mexer no resto.
