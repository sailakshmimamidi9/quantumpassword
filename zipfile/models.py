from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

db = SQLAlchemy()
password_hasher = PasswordHasher()


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(80), unique=True, nullable=False, index=True
    )
    email = db.Column(
        db.String(255), unique=True, nullable=False, index=True
    )
    master_password_hash = db.Column(db.String(255), nullable=False)

    password_records = db.relationship(
        "PasswordRecord",
        backref="owner",
        lazy=True
    )

    def set_master_password(self, master_password):
        self.master_password_hash = password_hasher.hash(master_password)

    def verify_master_password(self, master_password):
        try:
            return password_hasher.verify(
                self.master_password_hash, master_password
            )
        except (VerifyMismatchError, VerificationError, ValueError):
            return False


class PasswordRecord(db.Model):
    __tablename__ = "password_record"

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(120), nullable=False)
    account_username = db.Column(
        db.String(255), nullable=False, default=""
    )
    encrypted_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )