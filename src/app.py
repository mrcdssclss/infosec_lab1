import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import BadRequest

from src.security import hash_password, safe_display, valid_password, valid_username, verify_password


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE", str(Path(__file__).resolve().parent.parent / "secure_api.db")),
        JWT_SECRET=os.environ.get("JWT_SECRET", ""),
        JWT_ISSUER="ib-lab1-local",
        JWT_TTL_MINUTES=20,
        MAX_CONTENT_LENGTH=8192,
    )
    if config:
        app.config.update(config)
    if not app.config["JWT_SECRET"] or len(app.config["JWT_SECRET"]) < 32:
        raise RuntimeError("Set JWT_SECRET to a random secret of at least 32 characters")

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection:
            connection.close()

    def init_db():
        with app.app_context():
            db().execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL)")
            db().execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id))")
            db().commit()

    app.init_db = init_db

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    def json_object():
        if not request.is_json:
            return None
        obj = request.get_json(silent=True)
        return obj if isinstance(obj, dict) else None

    def authorized(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            authorization = request.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                return jsonify(error="Bearer token required"), 401
            try:
                token = authorization[7:]
                claims = jwt.decode(
                    token,
                    app.config["JWT_SECRET"],
                    algorithms=["HS256"],
                    audience="ib-lab1-api",
                    issuer=app.config["JWT_ISSUER"],
                    options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                )
                g.user_id = int(claims["sub"])
            except (jwt.PyJWTError, ValueError, TypeError):
                return jsonify(error="Invalid or expired token"), 401
            return view(*args, **kwargs)
        return wrapper

    @app.post("/auth/register")
    def register():
        body = json_object()
        if body is None or not valid_username(body.get("username")) or not valid_password(body.get("password")):
            return jsonify(error="username must be 3-32 letters/digits/_; password 12-128 characters"), 400
        try:
            cursor = db().execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (body["username"], hash_password(body["password"])),
            )
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify(error="Username is already registered"), 409
        return jsonify(id=cursor.lastrowid, username=body["username"]), 201

    @app.post("/auth/login")
    def login():
        body = json_object()
        if body is None or not isinstance(body.get("username"), str) or not isinstance(body.get("password"), str):
            return jsonify(error="Invalid credentials"), 401
        user = db().execute("SELECT id, password_hash FROM users WHERE username = ?", (body["username"],)).fetchone()
        if user is None or not verify_password(user["password_hash"], body["password"]):
            return jsonify(error="Invalid credentials"), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {"sub": str(user["id"]), "iss": app.config["JWT_ISSUER"], "aud": "ib-lab1-api", "iat": now, "exp": now + timedelta(minutes=app.config["JWT_TTL_MINUTES"])},
            app.config["JWT_SECRET"], algorithm="HS256"
        )
        return jsonify(access_token=token, token_type="Bearer", expires_in=app.config["JWT_TTL_MINUTES"] * 60)

    @app.get("/api/data")
    @authorized
    def data():
        notes = db().execute("SELECT id, content FROM notes WHERE user_id = ? ORDER BY id", (g.user_id,)).fetchall()
        return jsonify(items=[{"id": n["id"], "content": safe_display(n["content"])} for n in notes])

    @app.post("/api/data")
    @authorized
    def add_note():
        body = json_object()
        content = body.get("content") if body else None
        if not isinstance(content, str) or not 1 <= len(content.strip()) <= 500:
            return jsonify(error="content must be 1-500 characters"), 400
        cursor = db().execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (g.user_id, content.strip()))
        db().commit()
        return jsonify(id=cursor.lastrowid, content=safe_display(content.strip())), 201

    return app


if __name__ == "__main__":
    application = create_app()
    application.init_db()
    application.run(host="127.0.0.1", port=5000, debug=False)
