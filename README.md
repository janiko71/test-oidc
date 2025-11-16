# test-oidc

Lab de découverte d'OIDC dans Codespaces (github). Documentation plus complèt en cours d'élaboration.

L'objectif de ce petit lab est uniquement de comprendre le fonctionnement et les mécanismes de sécurité d'OIDC, et n'est absolument pas destiné à la production, puisqu'il affiche en clair des informations importantes.

## Première version stable

Version optimisée pour Codespace, avec gestion des redirections de ports.

## Améliorations

### Ajout de PKCE

**PKCE** (= Proof Key for Code Exchange) ajoute une protection en plus :

Au `/login`, le client génère :
* un code_verifier (secret, gardé côté client),
* un code_challenge = base64url(SHA256(code_verifier)) envoyé à Keycloak.

Au `/auth/callback`, quand on échange le code contre les tokens, on envoie le code_verifier.
* Keycloak vérifie que code_verifier matche le code_challenge utilisé au départ.

→ Ça empêche un attaquant qui volerait le code (dans les logs, le navigateur, un proxy…) de l’échanger sans aussi connaître le code_verifier.

## Commandes importantes
```
python -m venv .venv
source .venv/bin/activate # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
