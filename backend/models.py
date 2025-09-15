# backend/models.py
import enum
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.sqlite import JSON as SQLITE_JSON
from sqlalchemy.dialects.postgresql import JSONB as POSTGRESQL_JSONB

db = SQLAlchemy()

roles_users = db.Table('roles_users', db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True), db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True))
class Role(db.Model): __tablename__ = "roles"; id = db.Column(db.Integer, primary_key=True); name = db.Column(db.String(80), unique=True, nullable=False); description = db.Column(db.String(255))
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    roles = db.relationship('Role', secondary=roles_users, lazy='subquery', backref=db.backref('users', lazy=True))
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
class Institution(db.Model): __tablename__ = "institutions"; id = db.Column(db.Integer, primary_key=True); name = db.Column(db.String(255), unique=True, nullable=False); admin_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True); certificates = db.relationship("Certificate", backref="institution", lazy=True, cascade="all, delete-orphan")
class CertificateStatus(enum.Enum): VALID = "valid"; REVOKED = "revoked"; EXPIRED = "expired"
class Certificate(db.Model):
    __tablename__ = "certificates"
    id = db.Column(db.Integer, primary_key=True)
    institution_id = db.Column(db.Integer, db.ForeignKey("institutions.id"), nullable=False)
    cert_id = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    roll = db.Column(db.String(100), nullable=True)
    course = db.Column(db.String(255), nullable=True)
    marks = db.Column(db.String(100), nullable=True)
    file_hash = db.Column(db.String(255), nullable=True, index=True)
    data_hash = db.Column(db.String(255), nullable=True, index=True)
    issued_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.Enum(CertificateStatus), nullable=False, default=CertificateStatus.VALID)
    blockchain_tx_hash = db.Column(db.String(255), nullable=True, index=True)
    certificate_metadata = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    verification_logs = db.relationship("VerificationLog", backref="certificate", lazy=True)
    def to_dict(self):
        return {
        "id": self.cert_id,  # KEY FIX: Changed "cert_id" to "id" to match the frontend table
        "name": self.name,
        "institution": self.institution.name if self.institution else "N/A", # KEY FIX: Added the institution's name
        "status": self.status.value,
        "issued_date": self.issued_date.isoformat() if self.issued_date else None, # KEY FIX: Added the formatted issue date
        "file_hash": self.file_hash # Included for our next step
     }

# CHANGE: Replaced old statuses with new, more descriptive and user-friendly labels.
class VerificationResult(str, enum.Enum):
    VERIFIED_VIA_REGISTRY = "Verified via Registry"
    MANUAL_CHECK_REQUIRED = "High Confidence - Manual Check Recommended"
    LIKELY_FORGED = "Likely Forged"
    DOCUMENT_REVOKED = "Document Revoked"  # <-- ADD THIS LINE
    NOT_A_CERTIFICATE = "Unsupported Document Type"
    NOT_FOUND_IN_REGISTRY = "Not Found in External Registry"
    ERROR = "System Error"

class VerificationLog(db.Model):
    __tablename__ = "verification_logs"
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # --- NEW COLUMNS START HERE ---
    filename = db.Column(db.String(255), nullable=True)
    file_hash = db.Column(db.String(255), nullable=True, index=True)
    source = db.Column(db.String(50), nullable=True) # e.g., "Database", "DigiLocker", "Forgery Check"
    trust_score = db.Column(db.Integer, nullable=True)
    # --- NEW COLUMNS END HERE ---
    
    result = db.Column(db.Enum(VerificationResult), nullable=False)
    reasons = db.Column(db.Text, nullable=True)
    verifier_ip_address = db.Column(db.String(45), nullable=True)
    
    # We will now store the user's local time directly as a string
    timestamp_local = db.Column(db.String(100), nullable=True) 
    timestamp_utc = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) # Keep UTC for internal reference
    
    verifier = db.relationship('User', backref='verification_logs')

    def to_dict(self):
        return {
            # Use the new local timestamp for display
            "timestamp": self.timestamp_local or self.timestamp_utc.isoformat(), 
            "verifier": self.verifier.username if self.verifier else "Guest",
            "result": self.result.value,
            "reasons": self.reasons.split(',') if self.reasons else [],
            "ip_address": self.verifier_ip_address,
            # Add the new data to the response for the frontend
            "filename": self.filename,
            "file_hash": self.file_hash,
            "source": self.source,
            "trust_score": self.trust_score
        }

class MockCertificate(db.Model):
    __tablename__ = "mock_digilocker_certificates"
    id = db.Column(db.Integer, primary_key=True); institution = db.Column(db.String(255), nullable=False); cert_id = db.Column(db.String(255), unique=True, nullable=False, index=True); name = db.Column(db.String(255), nullable=False); roll = db.Column(db.String(128), nullable=True); file_hash = db.Column(db.String(128), nullable=True); created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    def to_dict(self): return { "cert_id": self.cert_id, "name": self.name, "roll": self.roll, "file_hash": self.file_hash }
class TokenBlocklist(db.Model): __tablename__ = "token_blocklist"; id = db.Column(db.Integer, primary_key=True); jti = db.Column(db.String(36), nullable=False, index=True); created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
class Alert(db.Model): __tablename__ = "alerts"; id = db.Column(db.Integer, primary_key=True); user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False); message = db.Column(db.String(512), nullable=False); is_read = db.Column(db.Boolean, default=False, nullable=False); timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False); user = db.relationship('User', backref='alerts')
class GuestVerification(db.Model): __tablename__ = "guest_verifications"; id = db.Column(db.Integer, primary_key=True); file_hash = db.Column(db.String(255), unique=True, nullable=False, index=True); result_cache = db.Column(db.JSON().with_variant(POSTGRESQL_JSONB, "postgresql").with_variant(SQLITE_JSON, "sqlite")); first_verified_at = db.Column(db.DateTime, default=datetime.utcnow); last_verified_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)