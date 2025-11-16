# test-oidc

## Première version stable

Version optimisée pour Codespace, avec gestion des redirections de ports.

```
python -m venv .venv
source .venv/bin/activate # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
