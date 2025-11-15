import os
from jwt import PyJWKClient
import jwt
from dotenv import load_dotenv

load_dotenv()

REALM = os.environ.get("KEYCLOAK_REALM", "demo-jean")
INTERNAL_HOST = os.environ.get("KEYCLOAK_INTERNAL_HOST", "http://localhost:8080").rstrip("/")

# URL JWKS interne de Keycloak
JWKS_URL = f"{INTERNAL_HOST}/realms/{REALM}/protocol/openid-connect/certs"

_jwks_client = PyJWKClient(JWKS_URL)


def verify_access_token(token: str, audience: str | None = None) -> dict:
    """
    Vérifie un access_token JWT signé par Keycloak :
      - récupère la clé publique via la JWKS
      - vérifie la signature
      - retourne les claims
    """
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
    except Exception as e:
        raise Exception(f"Erreur JWKS: {e}")

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            options={"verify_aud": audience is not None},
        )
        return claims
    except Exception as e:
        raise Exception(f"Erreur vérification JWT: {e}")
