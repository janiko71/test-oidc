# Connecter FastAPI à Keycloak en environnement proxifié

Ce tutoriel détaille pas à pas comment réaliser une authentification OpenID Connect (OIDC) entre une application **FastAPI** et **Keycloak**, **dans un environnement proxifié** (GitHub Codespaces, tunnels, reverse proxies, ingress Kubernetes…).

Il couvre :
- Les contraintes liées aux proxys et URL internes/externes
- La configuration de Keycloak
- L’application FastAPI (avec PKCE)
- La gestion des cookies, sessions, SameSite, Secure
- Les pièges classiques et leur résolution

---

## 1. Comprendre les défis d’un environnement proxifié

Lorsqu’on utilise des environnements tels que **GitHub Codespaces**, **Gitpod**, **ngrok**, un **reverse proxy**, ou un **ingress Kubernetes**, on a :

### **Deux vues différentes des services**
- **Vue externe (navigateur)** : l’utilisateur accède au service via une URL publique fournie par le proxy.
- **Vue interne (conteneurs / backend)** : les services se parlent en local, ex : `http://localhost:8080`.

### Exemple :
| Composant | Vue externe | Vue interne |
|----------|-------------|-------------|
| Keycloak | https://abc123-8080.app.github.dev | http://localhost:8080 |
| FastAPI  | https://abc123-8000.app.github.dev | http://localhost:8000 |

### Conséquence majeure
➡️ Le **redirect_uri** doit correspondre exactement à l’URL **vue par l’utilisateur**, pas celle vue par le conteneur.

➡️ Les endpoints `/token` et `/userinfo` doivent utiliser **les URLs internes**.

---

## 2. Configuration des variables d’environnement

Créer un fichier `.env` :

```ini
# --- Keycloak ---
KEYCLOAK_REALM=demo-jean

# URL vue par le navigateur (via proxy)
KEYCLOAK_EXTERNAL_HOST=https://abc123-8080.app.github.dev

# URL interne utilisée par FastAPI/HTTPX
KEYCLOAK_INTERNAL_HOST=http://localhost:8080

# --- Application ---
OIDC_CLIENT_ID=fastapi-app
BASE_URL=https://abc123-8000.app.github.dev

APP_SECRET=change-me-please
```

⚠️ Important :
- `EXTERNAL_HOST` sert pour `/auth` (navigateur).
- `INTERNAL_HOST` sert pour `/token` et `/userinfo`.

---

## 3. Configuration Keycloak

### 3.1. Créer un client public
Dans **Clients → Create** :
- **Client ID** : `fastapi-app`
- **Type** : Public client
- **Standard Flow (code)** : ✔️
- **Direct Access Grants** : ❌
- **Client authentication** : ❌

### 3.2. Configurer les redirect URIs
Très important : l’URL doit être exactement celle vue par le navigateur :

```
https://abc123-8000.app.github.dev/auth/callback
```

### 3.3. Configurer Web Origins
```
https://abc123-8000.app.github.dev/*
```

### 3.4. Désactiver l’obligation du secret client
(Sinon erreur `invalid_client`.)

---

## 4. Application FastAPI complète (avec PKCE)

### 4.1 Structure des fichiers
```
app/
 ├── main.py
 ├── security.py
 ├── templates/
 │    ├── home.html
 │    └── profile.html
 └── static/style.css
.env
```

### 4.2 Code Python : génération du code_challenge (PKCE)
```python
import secrets
import hashlib
import base64

def generate_pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge
```

### 4.3 URL OIDC
```python
AUTH_URL   = f"{EXTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_URL  = f"{INTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/token"
USERINFO_URL = f"{INTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/userinfo"
```

### 4.4 Route /login
```python
@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(16)
    verifier, challenge = generate_pkce()

    request.session["state"] = state
    request.session["pkce_verifier"] = verifier

    redirect_uri = f"{BASE_URL}/auth/callback"

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return RedirectResponse(AUTH_URL + "?" + urlencode(params))
```

### 4.5 Callback OIDC
```python
@app.get("/auth/callback")
async def auth_callback(request: Request):
    state = request.query_params.get("state")
    code = request.query_params.get("code")

    if state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="state invalide")

    verifier = request.session.get("pkce_verifier")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": f"{BASE_URL}/auth/callback",
                "code_verifier": verifier,
            }
        )

    token = resp.json()
    access = token.get("access_token")

    async with httpx.AsyncClient() as client:
        ui = await client.get(USERINFO_URL, headers={"Authorization": f"Bearer {access}"})

    request.session["user"] = ui.json()

    return RedirectResponse("/")
```

---

## 5. Problèmes fréquents et solutions

### 5.1 `Invalid redirect_uri`
Causes possibles :
- URL pas exactement identique (différence de `/`, de HTTPS…)
- mauvais port (8000 vs 8080)
- CODESPACES change l’URL → il faut mettre la bonne valeur dans Keycloak

### 5.2 `invalid_grant: Code not valid`
Causes :
- callback appelé deux fois
- mauvais `code_verifier` PKCE
- cookie SameSite bloqué → session perdue

### Solutions :
Ajouter dans FastAPI :
```python
SessionMiddleware(secret_key=APP_SECRET, same_site="none", https_only=True)
```

### 5.3 Le CSS ne charge pas
Problème typique de proxys → les URL absolues cassent.

Solution : utiliser :
```html
<link rel="stylesheet" href="/static/style.css">
```

### 5.4 Les cookies ne sont pas envoyés
Toujours mettre :
- `Secure` si HTTPS
- `SameSite=None`

---

## 6. Tester l’API protégée
Une fois authentifié, aller sur `/protected`, copier l'access_token, puis :

```bash
curl -H "Authorization: Bearer eyJ..." \
     https://abc123-8000.app.github.dev/api/resource
```

### Réponse :
```json
{
  "ok": true,
  "sub": "ffc9d5d3-7f12-40c3-9496-53bb0207e106",
  "email": "testuser@example.com"
}
```

---

## 7. Checklist de fonctionnement

### ✔️ Redirect URI identique navigateur / Keycloak
### ✔️ Keycloak INTERNAL pour token/userinfo
### ✔️ PKCE activé
### ✔️ Cookies SameSite=None + Secure
### ✔️ Sessions correctement stockées
### ✔️ CSRF state vérifié

---

## 8. Conclusion
Ce tutoriel présente une solution propre et robuste pour exécuter FastAPI + Keycloak en environnement proxifié. Il prend en compte :
- La distinction critique **URLs internes / externes**
- Les problèmes de cookies
- La compatibilité Codespaces / ngrok
- Un flow OIDC moderne et sécurisé (PKCE)

Vous disposez maintenant d’un véritable **laboratoire complet**, réutilisable dans n’importe quel contexte proxy / reverse-proxy / conteneur / cloud.

Besoin de la version PDF ? de diagrammes d’architecture ? Je peux les générer.

