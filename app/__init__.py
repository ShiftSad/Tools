"""Flask application factory."""
import os
import pathlib

from flask import Flask, redirect, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .config import Config
from .db import close_db, init_schema

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLIC_DIR = ROOT / "public"

limiter = Limiter(key_func=get_remote_address, default_limits=[], headers_enabled=True)


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    # Behind Railway's proxy — trust X-Forwarded-For so rate-limiting and
    # report IPs reflect the actual client.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    init_schema(app)
    limiter.init_app(app)
    app.teardown_appcontext(close_db)

    from .scan import bp as scan_bp
    from .admin import bp as admin_bp
    from .failmark import bp as failmark_bp
    app.register_blueprint(scan_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(failmark_bp, url_prefix="/api")

    from .passmark_sync import start_background_sync
    start_background_sync(app)

    # ── routing ──
    # 1) Any *.html URL → 301 to its canonical extensionless form.
    # 2) /                 → index.html (which itself bounces to /dependency-extractor).
    # 3) /<name>           → if public/<name>.html exists, serve it. Else try as a
    #                        literal file under public/ (so .css, .js, assets work).
    @app.route("/<path:slug>.html")
    def html_redirect(slug):
        return redirect(f"/{slug}", code=301)

    @app.route("/")
    def root():
        return send_from_directory(PUBLIC_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        if any(part.startswith(".") for part in filename.split("/")):
            return ("not found", 404)
        # extensionless pretty URL — prefer the html version
        pretty = PUBLIC_DIR / f"{filename}.html"
        if pretty.is_file():
            return send_from_directory(PUBLIC_DIR, f"{filename}.html")
        full = PUBLIC_DIR / filename
        if full.is_file():
            return send_from_directory(PUBLIC_DIR, filename)
        return ("not found", 404)

    @app.route("/healthz")
    def healthz():
        return {"ok": True}

    return app
