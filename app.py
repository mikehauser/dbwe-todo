import os

from flask import Flask, render_template, request, redirect, url_for
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os, secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# --- Pfade vorbereiten ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "app.db")

# --- App konfigurieren ---
app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-in-prod"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH.replace("\\", "/")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- User Modell ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class APIToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FocusSession(db.Model):
    __tablename__ = "focus_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    label = db.Column(db.String(120), nullable=False)
    minutes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Task Modell ---
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    done = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("tasks", lazy=True))

# --- Route ---
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # einfache Validierung
        if not username or not email or not password:
            return "Bitte alle Felder ausfüllen.", 400

        # existiert schon?
        if User.query.filter((User.username == username) | (User.email == email)).first():
            return "Benutzername oder E-Mail bereits vergeben.", 400

        # anlegen
        u = User(username=username, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        return redirect(url_for("home"))

    # GET
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        u = User.query.filter_by(email=email).first()
        if not u or not u.check_password(password):
            return "Ungültige Anmeldedaten.", 401
        login_user(u)
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    return f"Hallo, {current_user.username}!"

@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title:
            return "Titel darf nicht leer sein.", 400
        t = Task(title=title, description=description, user=current_user)
        db.session.add(t)
        db.session.commit()
        return redirect(url_for("tasks"))

    user_tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template("tasks.html", tasks=user_tasks)

@app.route("/tasks/<int:task_id>/done")
@login_required
def task_done(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return "Nicht erlaubt!", 403
    task.done = True
    db.session.commit()
    return redirect(url_for("tasks"))

@app.route("/tasks/<int:task_id>/delete")
@login_required
def task_delete(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return "Nicht erlaubt!", 403
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("tasks"))


@app.route("/token", methods=["GET", "POST"])
@login_required
def token_page():
    t = APIToken.query.filter_by(user_id=current_user.id).first()
    if not t or request.method == "POST":
        tok = secrets.token_hex(16)
        if not t:
            t = APIToken(user_id=current_user.id, token=tok)
            db.session.add(t)
        else:
            t.token = tok
        db.session.commit()
    return render_template("token.html", token=t.token)

def api_user_from_request():
    auth = request.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("X-API-KEY")
    if not token:
        return None
    t = APIToken.query.filter_by(token=token).first()
    return User.query.get(t.user_id) if t else None

@app.route("/api/sessions", methods=["GET", "POST"])
def api_sessions():
    user = api_user_from_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        rows = FocusSession.query.filter_by(user_id=user.id).order_by(FocusSession.created_at.desc()).all()
        return jsonify([{
            "id": r.id, "label": r.label, "minutes": r.minutes, "created_at": r.created_at.isoformat()
        } for r in rows])

    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()
    try:
        minutes = int(data.get("minutes", 0))
    except (TypeError, ValueError):
        minutes = 0
    if not label or minutes <= 0:
        return jsonify({"error": "label and positive minutes required"}), 400

    fs = FocusSession(user_id=user.id, label=label, minutes=minutes)
    db.session.add(fs)
    db.session.commit()
    return jsonify({"id": fs.id, "label": fs.label, "minutes": fs.minutes, "created_at": fs.created_at.isoformat()}), 201

# --- Main ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # legt DB+Tabellen an (falls nicht vorhanden)
    app.run(debug=True)

