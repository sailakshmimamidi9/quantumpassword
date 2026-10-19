import os
import secrets
import string
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, login_user, login_required,
    logout_user, current_user
)
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash
from sqlalchemy import or_

from models import db, User, PasswordRecord

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)


def load_or_create_key(path):
    if path.exists():
        return path.read_bytes().strip()

    key = Fernet.generate_key()
    with open(path, "xb") as file:
        file.write(key)

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    return key


app = Flask(__name__, instance_path=str(INSTANCE_DIR))

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY"
) or load_or_create_key(INSTANCE_DIR / "secret.key")

database_url = os.environ.get("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://", "postgresql://", 1
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + str(BASE_DIR / "quantum_passwords.db")
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

key_from_environment = os.environ.get("PASSWORD_ENCRYPTION_KEY")

if key_from_environment:
    encryption_key = key_from_environment.encode("ascii")
else:
    encryption_key = load_or_create_key(
        INSTANCE_DIR / "password.key"
    )

cipher = Fernet(encryption_key)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def verify_master_password(user, password):
    if user.verify_master_password(password):
        return True

    try:
        return check_password_hash(
            user.master_password_hash, password
        )
    except (ValueError, TypeError):
        return False


def vault_page(revealed_record_id=None, revealed_password=None):
    records = PasswordRecord.query.filter_by(
        user_id=current_user.id
    ).order_by(PasswordRecord.id.desc()).all()

    return render_template(
        "vault.html",
        records=records,
        revealed_record_id=revealed_record_id,
        revealed_password=revealed_password
    )


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("master_password", "")

        if not username or not email or not password:
            flash("Please complete every field.")
            return render_template("register.html")

        if len(password) < 12:
            flash("Master password must be at least 12 characters.")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("That username is already registered.")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("That email is already registered.")
            return render_template("register.html")

        user = User(username=username, email=email)
        user.set_master_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("master_password", "")

        user = User.query.filter(
            or_(
                User.username == identity,
                User.email == identity.lower()
            )
        ).first()

        if user and verify_master_password(user, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid username/email or master password.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return vault_page()


@app.route("/generate", methods=["POST"])
@login_required
def generate():
    service = request.form.get("service_name", "").strip()
    account_username = request.form.get(
        "account_username", ""
    ).strip()

    try:
        length = int(request.form.get("password_length", "16"))
    except (TypeError, ValueError):
        flash("Enter a valid password length.")
        return redirect(url_for("dashboard"))

    if not service:
        flash("Choose or enter a service name.")
        return redirect(url_for("dashboard"))

    if not 8 <= length <= 64:
        flash("Password length must be between 8 and 64.")
        return redirect(url_for("dashboard"))

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(
        secrets.choice(alphabet) for _ in range(length)
    )

    encrypted = cipher.encrypt(
        password.encode("utf-8")
    ).decode("ascii")

    record = PasswordRecord(
        user_id=current_user.id,
        service_name=service,
        account_username=account_username,
        encrypted_password=encrypted
    )

    db.session.add(record)
    db.session.commit()

    flash("Password generated, encrypted, and saved.")
    return redirect(url_for("dashboard"))


@app.route("/reveal/<int:record_id>", methods=["GET", "POST"])
@login_required
def reveal_password(record_id):
    record = PasswordRecord.query.filter_by(
        id=record_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        encrypted = record.encrypted_password

        if isinstance(encrypted, str):
            encrypted = encrypted.encode("ascii")

        password = cipher.decrypt(encrypted).decode("utf-8")

    except (InvalidToken, ValueError, UnicodeError):
        flash(
            "Could not decrypt this record. "
            "The original encryption key may be needed."
        )
        return redirect(url_for("dashboard"))

    return vault_page(record.id, password)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)