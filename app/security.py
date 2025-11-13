import time
import httpx
from functools import lru_cache
from jose import jwt
from jose.utils import base64url_decode
from typing import Dict, Any

class JWKSClient:
    def __init__(self, issuer: str):
        self.issuer = issuer.rstrip('/')
        self._openid_cfg_url = f"{self.issuer}/.well-known/openid-configuration"

    @lru_cache(maxsize=1)
    def openid_config(self) -> Dict[str, Any]:
        r = httpx.get(self._openid_cfg_url, timeout=10)
        r.raise_for_status()
        return r.json()

    @lru_cache(maxsize=1)
    def jwks(self) -> Dict[str, Any]:
        jwks_uri = self.openid_config()["jwks_uri"]
        r = httpx.get(jwks_uri, timeout=10)
        r.raise_for_status()
        return r.json()

    def verify_access_token(self, token: str, audience: str | None = None) -> Dict[str, Any]:
        # Trouver la bonne clé par kid
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")
        key = None
        for jwk in self.jwks().get("keys", []):
            if jwk.get("kid") == kid:
                key = jwk
                break
        if not key:
            raise ValueError("JWK introuvable pour ce kid")

        claims = jwt.decode(
            token,
            key,
            algorithms=[key.get("alg", "RS256"), "RS256"],
            audience=audience,
            issuer=self.issuer,
            options={"verify_aud": audience is not None}
        )
        # Vérifications basiques supplémentaires
        now = int(time.time())
        if claims.get("exp") and now > int(claims["exp"]):
            raise ValueError("Token expiré")
        return claims