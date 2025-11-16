import os
import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, HTTPException, Security
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv

from app.security import verify_access_token  # <--- important

load_dotenv()

# -----------------------------
# Fonctions pour PKCE
# -----------------------------

def generate_code_verifier() -> str:
    # 32 octets → ~43 caractères en base64url, dans les clous de la RFC
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
    print("CODE_VERIFIER:", verifier)
    return verifier.decode("ascii")


def generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=")
    print("CODE_CHALLENGE:", challenge)
    return challenge.decode("ascii")

# -----------------------------
# Configuration depuis les variables d'environnement
# -----------------------------

REALM = os.environ.get("KEYCLOAK_REALM", "demo-jean")
INTERNAL_HOST = os.environ.get("KEYCLOAK_INTERNAL_HOST", "http://localhost:8080").rstrip("/")
EXTERNAL_HOST = os.environ.get("KEYCLOAK_EXTERNAL_HOST", INTERNAL_HOST).rstrip("/")

CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")

AUTH_URL = f"{EXTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_URL = f"{INTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/token"

# -----------------------------
# Application FastAPI
# . Construction app et chargement du template HTML
# . Lancement app: uvicorn app.main:app --reload
# -----------------------------

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=APP_SECRET,
    same_site="lax",
    https_only=True,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

# -----------------------------
# Routes
# -----------------------------

def get_user(session):
    return session.get("user")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_user(request.session)
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(16)
    request.session["state"] = state

    # PKCE : générer un code_verifier et le stocker en session
    code_verifier = generate_code_verifier()
    request.session["code_verifier"] = code_verifier

    # PKCE : calculer le code_challenge
    code_challenge = generate_code_challenge(code_verifier)

    redirect_uri = f"{BASE_URL}/auth/callback"

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
        # PKCE 
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    url = AUTH_URL + "?" + urlencode(params)
    print("REDIRECT TO", url)
    return RedirectResponse(url)

@app.get("/auth/callback")
async def auth_callback(request: Request):
    print("CALLBACK HIT with params:", dict(request.query_params))

    state = request.query_params.get("state")
    code = request.query_params.get("code")

    if not state or state != request.session.get("state"):
        raise HTTPException(status_code=400, detail=f"state invalide ({state=} session={request.session.get('state')})")

    if not code:
        raise HTTPException(status_code=400, detail="code manquant")

    redirect_uri = f"{BASE_URL}/auth/callback"

    # Récupérer le code_verifier PKCE de la session
    code_verifier = request.session.get("code_verifier")
    if not code_verifier:
        raise HTTPException(status_code=400, detail="code_verifier manquant en session (PKCE)")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )

    # On peut nettoyer le verifier de la session
    request.session.pop("code_verifier", None)

    print("TOKEN_RESP STATUS", token_resp.status_code, token_resp.text)

    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur token_endpoint: {token_resp.status_code} {token_resp.text}",
        )

    token = token_resp.json()
    access_token = token.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Pas d'access_token dans la réponse")

    try:
        claims = verify_access_token(access_token, audience=None)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur vérification token: {e}")

    print("CLAIMS DÉCODÉS:", claims)

    # On stocke des infos légères dans la session
    request.session["user"] = {
        "sub": claims.get("sub"),
        "name": claims.get("name") or claims.get("preferred_username"),
        "email": claims.get("email"),
    }
    # On complète par un sous-ensemble des claims pour les afficher dans le profil
    request.session["claims"] = {
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "name": claims.get("name"),
        "given_name": claims.get("given_name"),
        "family_name": claims.get("family_name"),
        "email": claims.get("email"),
        "email_verified": claims.get("email_verified"),
        "iss": claims.get("iss"),
        "aud": claims.get("aud"),
        "scope": claims.get("scope"),
        "realm_roles": claims.get("realm_access", {}).get("roles", []),
        "resource_access": claims.get("resource_access", {}),
        "exp": claims.get("exp"),
        "iat": claims.get("iat"),
    }

    # PAS de token en session, pour garder le cookie petit
    return RedirectResponse("/")

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

@app.get("/protected")
async def protected(request: Request):
    user = get_user(request.session)
    if not user:
        return RedirectResponse("/login")

    return JSONResponse(
    content={
        "message": "Vous êtes authentifié via OIDC",
        "user": user,
        "note": "Le token n'est pas stocké en session pour éviter un cookie trop gros.",
        "api_hint": "Appelez /api/resource avec Authorization: Bearer <access_token> que vous aurez récupéré au moment du callback.",
    },
    media_type="application/json; charset=utf-8",
)

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    user = get_user(request.session)
    if not user:
        return RedirectResponse("/login")

    claims = request.session.get("claims", {})
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "claims": claims,
        },
    )



bearer_scheme = HTTPBearer(auto_error=False)


@app.get("/api/resource")
async def api_resource(creds: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if not creds:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = creds.credentials
    try:
        claims = verify_access_token(token, audience=None)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    return {
        "ok": True,
        "sub": claims.get("sub"),
        "scope": claims.get("scope"),
        "claims": {k: claims.get(k) for k in ("iss", "aud", "exp", "iat", "email", "preferred_username")},
    }


@app.get("/debug-session")
async def debug_session(request: Request):
    return JSONResponse({"session": dict(request.session)})
