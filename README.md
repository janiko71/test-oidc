# test-oidc

Cette mini-application Flask montre comment exposer un service web depuis Codebase.

## Lancer en local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PORT=8000 python -m app.main
```

Le serveur écoute explicitement sur `0.0.0.0`, ce qui permet à Codebase de le
publier via l'URL fournie. Le point d'entrée `/health` peut être utilisé pour un
simple check.
