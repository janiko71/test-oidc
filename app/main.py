import os
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeSerializer
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

from .security import JWKSClient

load_dotenv()

ISSUER = os.environ["KEYCLOAK_ISSUER"].rstrip('/')
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip('/')

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET)

templates = Jinja2Templates(directory="app/templates")

oauth = OAuth()
oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_kwargs={"scope": "openid profile email"},
)

jwks_client = JWKSClient(ISSUER)

# --- Helpers ---

def get_user(session):
    return session.get("user")

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = get_user(request.session)
    return templates.TemplateResponse("home.html", {"request": request, "user": user})


@app.get("/login")
async def login(request: Request):
    # PKCE + state sont gérés automatiquement par Authlib si besoin,
    # mais ajoutons un state explicite.
    request.session["state"] = secrets.token_urlsafe(16)
    redirect_uri = f"{BASE_URL}/auth/callback"
    return await oauth.keycloak.authorize_redirect(request, redirect_uri, state=request.session["state"])

@app.get("/auth/callback")
async def auth_callback(request: Request):
    state = request.query_params.get("state")
    if not state or state != request.session.get("state"):
        raise HTTPException(status_code=400, detail="state invalide")

    token = await oauth.keycloak.authorize_access_token(request)
    userinfo = token.get("userinfo") or await oauth.keycloak.parse_id_token(request, token)

    # Stocker un sous-ensemble non sensible en session
    request.session["user"] = {
        "sub": userinfo.get("sub"),
        "name": userinfo.get("name") or userinfo.get("preferred_username"),
        "email": userinfo.get("email"),
    }
    request.session["token"] = token # contient access_token / id_token / expires_at

    return RedirectResponse("/")

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    # Optional: rediriger vers l'endpoint de logout Keycloak côté front
    return RedirectResponse("/")


@app.get("/protected")
async def protected(request: Request):
    user = get_user(request.session)
    if not user:
        return RedirectResponse("/login")
    token = request.session.get("token", {})
    return JSONResponse({
        "message": "Vous êtes authentifié via OIDC",
        "user": user,
        "access_token_excerpt": (token.get("access_token", "")[:30] + "…") if token.get("access_token") else None,
        "id_token_excerpt": (token.get("id_token", "")[:30] + "…") if token.get("id_token") else None,
        "api_hint": "Essayez /api/resource avec Authorization: Bearer <access_token>"
    })

# --- API protégée par Bearer JWT (access_token) ---

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security

bearer_scheme = HTTPBearer(auto_error=False)

@app.get("/api/resource")
async def api_resource(creds: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    if not creds:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = creds.credentials
    try:
        claims = jwks_client.verify_access_token(token, audience=None) # Keycloak met souvent aud = client_id, ajustez si besoin
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
        
    return {"ok": True, "sub": claims.get("sub"), "scope": claims.get("scope"), "claims": {k: claims.get(k) for k in ("iss","aud","exp","iat","email","preferred_username")}}