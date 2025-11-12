import os
from flask import Flask

app = Flask(__name__)


@app.get("/health")
def healthcheck() -> dict[str, str]:
    """Return a simple payload so platform health checks succeed."""
    return {"status": "ok"}


@app.get("/")
def index() -> dict[str, str]:
    """Home endpoint letting the operator know the service is reachable."""
    return {"message": "Service en ligne"}


def _resolve_port() -> int:
    """Resolve the port from the PORT environment variable.

    Codebase exposes the application on whatever value it injects in PORT, so
    default to 8000 when the variable is missing.
    """
    try:
        return int(os.environ.get("PORT", 8000))
    except (TypeError, ValueError):
        return 8000


def main() -> None:
    """Entrypoint used by the container."""
    app.run(host="0.0.0.0", port=_resolve_port())


if __name__ == "__main__":
    main()
