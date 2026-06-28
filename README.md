# 📱 PRoCon Mobile

Admin BF4 pelo iPhone/Android — sem PC, direto do servidor.

```
iPhone/Android (Safari/Chrome)
        ↕  WSS (seguro)
Railway.app  ← proxy.py (gratuito)
        ↕  TCP RCON
andura.fragify.net:30018
```

---

## 🚀 Deploy em 3 passos

### Passo 1 — Sobe o backend no Railway

1. Acesse **railway.app** e faça login com sua conta GitHub
2. Clique em **New Project → Deploy from GitHub repo**
3. Selecione o repositório (pasta `backend`)
4. O Railway detecta o `Procfile` e sobe automaticamente
5. Vá em **Settings → Networking → Generate Domain**
6. Anota a URL gerada — ex: `procon-proxy.up.railway.app`

### Passo 2 — Coloca a URL do proxy no frontend

Abre `frontend/index.html` e na linha:
```javascript
const PROXY_URL = 'wss://procon-proxy.up.railway.app';
```
Substitui pela URL do seu Railway com `wss://` na frente.

### Passo 3 — Sobe o frontend no GitHub Pages

1. No seu repositório GitHub, vai em **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: `main` / Folder: `/frontend`
4. Salva — em ~2 minutos o site está em:
   `https://SEU_USUARIO.github.io/NOME_DO_REPO`

---

## 📲 Instalar no iPhone (sem App Store)

1. Abre o link no **Safari**
2. Toca em **Compartilhar** (ícone de seta para cima)
3. Toca em **Adicionar à Tela de Início**
4. Confirma — aparece como app na tela inicial

---

## 📱 Como usar

1. Abre o app
2. Na tela **Connect**, digita:
   - Host: `andura.fragify.net`
   - Port: `30018`
   - Password: sua senha RCON
3. Clica **Connect**

**Pronto.** O app conecta direto ao servidor BF4.

---

## 🎮 Funcionalidades

| Aba | Função |
|---|---|
| **Players** | Lista jogadores por time. Toque para ações. |
| **Chat** | Chat em tempo real. Envia para All/Team 1/Team 2. |
| **Map** | Mapa, placar, rotação, ações do servidor. |
| **Console** | RCON raw — qualquer comando. |

### Ações por jogador:
Kill · Kick · Move · Temp Ban (60min) · Permanent Ban

### Motivos de ban pré-configurados:
- Hacking/Cheating
- Being Disrespectful
- Team Killing
- Spawn Killing
- Attacking Enemy Base
- Team balance
- (e mais 3)

---

## 📁 Estrutura

```
procon-git/
├── frontend/
│   └── index.html     ← GitHub Pages
└── backend/
    ├── proxy.py       ← Railway
    ├── requirements.txt
    └── Procfile
```

---

## 💰 Custo

| Serviço | Plano | Custo |
|---|---|---|
| GitHub Pages | Free | R$ 0 |
| Railway | Hobby (500h/mês) | R$ 0 |
| **Total** | | **R$ 0** |

O Railway tem 500h gratuitas por mês — suficiente para uso normal.
Se precisar de mais, o plano pago é ~$5/mês.
