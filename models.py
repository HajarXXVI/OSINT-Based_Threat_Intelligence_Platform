from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')
    virustotal_key = db.Column(db.String(120), nullable=True)
    shodan_key = db.Column(db.String(120), nullable=True)
    theme = db.Column(db.String(20), default='cyan')
    alert_threshold = db.Column(db.String(20), default='HIGH')
    webhook_url = db.Column(db.String(255), nullable=True)
    enable_particles = db.Column(db.Boolean, default=True)
    enable_crt = db.Column(db.Boolean, default=True)


class ScanResult(db.Model):
    """
    Stores historical target lookups, aggregated API intelligence, and calculated risk scores.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Tracks which user ran the scan
    target = db.Column(db.String(100), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    geolocation_data = db.Column(db.Text, nullable=True)
    shodan_data = db.Column(db.Text, nullable=True)
    vt_data = db.Column(db.Text, nullable=True)
    whois_data = db.Column(db.Text, nullable=True)
    ssl_data = db.Column(db.Text, nullable=True)
    dns_data = db.Column(db.Text, nullable=True)
    findings_data = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default="Low")
    risk_color = db.Column(db.String(20), nullable=True)
    # Exposure vs Threat profile: whether the target is attackable by others
    # (exposure) or dangerous to others (threat), and the human verdict.
    exposure_index = db.Column(db.Float, default=0.0)
    threat_index = db.Column(db.Float, default=0.0)
    exposure_band = db.Column(db.String(20), default="LOW")
    threat_band = db.Column(db.String(20), default="LOW")
    profile = db.Column(db.String(120), default="Low Concern — Apparently Sound Resource")

    def __repr__(self):
        return f"<ScanResult {self.target} - Score: {self.risk_score}>"


class AuditLog(db.Model):
    """
    Audit trail for compliance: who scanned what and when.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)  # denormalized for easy display
    action = db.Column(db.String(50), nullable=False)  # e.g., 'scan_started', 'scan_completed', 'scan_failed'
    target = db.Column(db.String(100), nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv4 or IPv6
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON for extra context
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLog {self.username} - {self.action} - {self.target}>"