# Connecter FastAPI à Keycloak en environnement proxifié

---

## 1. Introduction

Ce guide explique comment connecter **FastAPI** à **Keycloak**, même dans un environnement *proxifié* comme **GitHub Codespaces**, où les URL internes (vue conteneur) diffèrent des URL externes (vue navigateur via tunnel HTTPS).

Il couvre :

- OIDC Authorization Code Flow  
- PKCE  
- Gestion d’un hôte interne/externe  
- Sécurisation API avec JWT  
- Sessions sécurisées  
- Debug avancé  
- Déploiement GitHub Pages

---

## 2. Architecture simplifiée

```
Navigateur → Codespaces (8000 HTTPS) → FastAPI
                    ↓
            Tunnel GitHub (8080 HTTPS)
                    ↓
                 Keycloak
```

Problème :  
- FastAPI accède à Keycloak via : **http://localhost:8080**  
- Le navigateur accède via : **https://xxxxx-8080.app.github.dev**

---

## 3. Fichier `.env`

```env
KEYCLOAK_REALM=demo-jean

KEYCLOAK_EXTERNAL_HOST=https://bookish-adventure-xxxx-8080.app.github.dev
KEYCLOAK_INTERNAL_HOST=http://localhost:8080

OIDC_CLIENT_ID=fastapi-app

BASE_URL=https://bookish-adventure-xxxx-8000.app.github.dev

APP_SECRET=change-me
```

---

## 4. Endpoints OIDC utiles

| Usage | URL |
|-------|-----|
| Authorization Endpoint | `${EXTERNAL_HOST}/realms/<realm>/protocol/openid-connect/auth` |
| Token Endpoint | `${INTERNAL_HOST}/realms/<realm>/protocol/openid-connect/token` |
| UserInfo | `${INTERNAL_HOST}/realms/<realm>/protocol/openid-connect/userinfo` |
| JWKs | `${EXTERNAL_HOST}/realms/<realm>/protocol/openid-connect/certs` |

---

## 5. PKCE

```python
import secrets, hashlib, base64

def generate_pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge
```

---

## 6. Route `/login`

```python
@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(16)
    code_verifier, code_challenge = generate_pkce()

    request.session["state"] = state
    request.session["code_verifier"] = code_verifier

    redirect_uri = f"{BASE_URL}/auth/callback"

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    return RedirectResponse(AUTH_URL + "?" + urlencode(params))
```

---

## 7. Route `/auth/callback`

```python
@app.get("/auth/callback")
async def auth_callback(request: Request):
    state = request.query_params.get("state")
    code = request.query_params.get("code")

    if state != request.session.get("state"):
        raise HTTPException(400, "Invalid state")

    redirect_uri = f"{BASE_URL}/auth/callback"

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "code_verifier": request.session.get("code_verifier"),
            },
        )
```

---

## 8. Stockage de l’utilisateur

```python
userinfo = ui_resp.json()

request.session["user"] = {
    "sub": userinfo.get("sub"),
    "name": userinfo.get("name"),
    "email": userinfo.get("email"),
}
```

---

## 9. Sécuriser l’API avec JWT

```python
from jwt import PyJWKClient

jwks_client = PyJWKClient(f"{EXTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/certs")

@app.get("/api/resource")
async def api_resource(creds: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    token = creds.credentials
    claims = jwks_client.decode_token(token)
    return {"ok": True, "claims": claims}
```

---

## 10. Erreurs fréquentes

| Erreur | Cause | Solution |
|--------|--------|---------|
| `invalid_grant` | mauvais redirect_uri | Vérifier dans Keycloak → Client |
| Perte de session | SameSite ou Secure | Activer `secure=True` |
| `Missing jwks_uri` | mauvais endpoint | Utiliser EXTERNAL_HOST |
