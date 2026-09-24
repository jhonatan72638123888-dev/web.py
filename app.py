"""
Sistema de login web 100% em Python (Flask + SQLite).

Como rodar:
    pip install flask
    python app.py
Depois abra: http://127.0.0.1:5000
"""

import os
import secrets
import sqlite3
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# Em produção, defina a variável de ambiente SECRET_KEY (senão as sessões
# são invalidadas toda vez que o servidor reinicia).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # SESSION_COOKIE_SECURE=True,  # ative quando usar HTTPS
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


# ----------------------------------------------------------------------------
# Banco de dados
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL,
                   created_at TEXT DEFAULT CURRENT_TIMESTAMP
               )"""
        )


# ----------------------------------------------------------------------------
# Segurança: CSRF + login obrigatório
# ----------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Token CSRF inválido.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para acessar essa página.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# ----------------------------------------------------------------------------
# Template (HTML + CSS dentro do próprio Python)
# ----------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #4f46e5, #7c3aed);
    }
    .card {
      background: #fff; width: min(92vw, 380px); padding: 32px;
      border-radius: 16px; box-shadow: 0 20px 50px rgba(0,0,0,.25);
    }
    h1 { margin: 0 0 6px; font-size: 1.6rem; color: #1f2937; }
    p.sub { margin: 0 0 22px; color: #6b7280; font-size: .95rem; }
    label { display: block; margin: 14px 0 6px; font-size: .85rem; color: #374151; font-weight: 600; }
    input {
      width: 100%; padding: 11px 12px; border: 1px solid #d1d5db;
      border-radius: 8px; font-size: 1rem; outline: none;
    }
    input:focus { border-color: #4f46e5; box-shadow: 0 0 0 3px rgba(79,70,229,.2); }
    button {
      width: 100%; margin-top: 22px; padding: 12px; border: 0; border-radius: 8px;
      background: #4f46e5; color: #fff; font-size: 1rem; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #4338ca; }
    .alt { margin-top: 18px; text-align: center; font-size: .9rem; color: #6b7280; }
    a { color: #4f46e5; text-decoration: none; font-weight: 600; }
    .msg { padding: 10px 12px; border-radius: 8px; margin-bottom: 14px; font-size: .9rem; }
    .msg.error { background: #fee2e2; color: #991b1b; }
    .msg.success { background: #dcfce7; color: #166534; }
    .logout { background: #ef4444; }
    .logout:hover { background: #dc2626; }
  </style>
</head>
<body>
  <main class="card">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="msg {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}

    {% if page == "login" %}
      <h1>Entrar</h1>
      <p class="sub">Acesse sua conta para continuar.</p>
      <form method="post" autocomplete="on">
        <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <label for="username">Usuário</label>
        <input id="username" name="username" required autofocus autocomplete="username">
        <label for="password">Senha</label>
        <input id="password" name="password" type="password" required autocomplete="current-password">
        <button type="submit">Entrar</button>
      </form>
      <div class="alt">Não tem conta? <a href="{{ url_for('register') }}">Cadastre-se</a></div>

    {% elif page == "register" %}
      <h1>Criar conta</h1>
      <p class="sub">Leva menos de um minuto.</p>
      <form method="post" autocomplete="on">
        <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <label for="username">Usuário</label>
        <input id="username" name="username" required minlength="3" maxlength="30"
               pattern="[A-Za-z0-9_.\\-]+" autofocus autocomplete="username">
        <label for="password">Senha (mín. 8 caracteres)</label>
        <input id="password" name="password" type="password" required minlength="8" autocomplete="new-password">
        <label for="confirm">Confirmar senha</label>
        <input id="confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password">
        <button type="submit">Cadastrar</button>
      </form>
      <div class="alt">Já tem conta? <a href="{{ url_for('login') }}">Entrar</a></div>

    {% elif page == "dashboard" %}
      <h1>Olá, {{ user.username }}! 👋</h1>
      <p class="sub">Você está logado. Conta criada em {{ user.created_at }}.</p>
      <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
        <button class="logout" type="submit">Sair</button>
      </form>
    {% endif %}
  </main>
</body>
</html>
"""


# ----------------------------------------------------------------------------
# Rotas
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if not (3 <= len(username) <= 30):
            error = "O usuário deve ter entre 3 e 30 caracteres."
        elif len(password) < 8:
            error = "A senha deve ter pelo menos 8 caracteres."
        elif password != confirm:
            error = "As senhas não coincidem."

        if error is None:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "Esse nome de usuário já está em uso."
            else:
                flash("Conta criada! Faça login.", "success")
                return redirect(url_for("login"))

        flash(error, "error")

    return render_template_string(PAGE, page="register", title="Cadastro")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()  # evita fixação de sessão
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        # Mensagem genérica: não revela se o usuário existe ou não
        flash("Usuário ou senha incorretos.", "error")

    return render_template_string(PAGE, page="login", title="Login")


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None:  # usuário removido do banco
        session.clear()
        return redirect(url_for("login"))
    return render_template_string(PAGE, page="dashboard", title="Painel", user=user)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Você saiu da conta.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
