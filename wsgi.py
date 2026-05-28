"""Entry point for gunicorn and local dev.

Production (Railway):
    gunicorn wsgi:app --bind 0.0.0.0:$PORT

Local dev:
    python wsgi.py
"""
from dotenv import load_dotenv
load_dotenv()  # noqa: must run before importing app

from app import create_app

app = create_app()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_ENV") == "development")
