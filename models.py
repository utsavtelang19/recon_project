import json
from datetime import datetime, date, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from config import PLAN_LIMITS, PLAN_NAMES

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Roles: 'admin', 'paid', 'free'
    role = db.Column(db.String(20), default='free', nullable=False)
    
    # Plans: 'free', 'monthly', 'annual', 'lifetime'
    plan_tier = db.Column(db.String(20), default='free', nullable=False)
    
    # Daily checks allowed: 50 (free), 200 (monthly), 500 (lifetime)
    daily_limit = db.Column(db.Integer, default=50, nullable=False)
    checks_today = db.Column(db.Integer, default=0, nullable=False)
    last_reset_date = db.Column(db.Date, default=date.today, nullable=False)
    total_scans = db.Column(db.Integer, default=0, nullable=False)
    
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    plan_expires_at = db.Column(db.DateTime, nullable=True) # Null for free or lifetime

    # Relationship to scans
    scans = db.relationship('ScanLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_paid(self):
        return self.role == 'paid' or self.plan_tier in ('monthly', 'annual', 'lifetime')

    def reset_quota_if_new_day(self):
        """Resets the checks_today quota if current local date is past last_reset_date (after midnight 12:00 AM)."""
        current_date = date.today()
        if self.last_reset_date is None or self.last_reset_date < current_date:
            self.checks_today = 0
            self.last_reset_date = current_date
            # Check if monthly/annual plan expired
            if self.plan_expires_at and datetime.utcnow() > self.plan_expires_at:
                self.role = 'free'
                self.plan_tier = 'free'
                self.daily_limit = PLAN_LIMITS['free']
                self.plan_expires_at = None
            db.session.commit()

    def get_remaining_checks(self):
        self.reset_quota_if_new_day()
        if self.is_admin():
            return 999999  # Admins have unlimited reconnaissance checks
        remaining = self.daily_limit - self.checks_today
        return max(0, remaining)

    def can_scan(self):
        """Returns (allowed: bool, remaining: int, message: str)"""
        self.reset_quota_if_new_day()
        if not self.is_active:
            return False, 0, "Account has been deactivated. Please contact the administrator."
        if self.is_admin():
            return True, 999999, "Admin unlimited access."
        
        remaining = self.daily_limit - self.checks_today
        if remaining <= 0:
            return False, 0, f"Daily limit reached ({self.checks_today}/{self.daily_limit} IP checks used). Quota resets at 12:00 AM midnight."
        return True, remaining, "Scan allowed."

    def consume_check(self):
        """Increments check counters and commits."""
        self.reset_quota_if_new_day()
        self.checks_today += 1
        self.total_scans += 1
        db.session.commit()

    def set_plan(self, tier):
        """Updates user tier, role, and daily limit."""
        tier = tier.lower()
        if tier not in PLAN_LIMITS:
            tier = 'free'
        self.plan_tier = tier
        self.daily_limit = PLAN_LIMITS[tier]
        if tier in ('monthly', 'annual', 'lifetime'):
            if self.role != 'admin':
                self.role = 'paid'
            if tier == 'monthly':
                self.plan_expires_at = datetime.utcnow() + timedelta(days=30)
            elif tier == 'annual':
                self.plan_expires_at = datetime.utcnow() + timedelta(days=365)
            elif tier == 'lifetime':
                self.plan_expires_at = None
        else:
            if self.role != 'admin':
                self.role = 'free'
            self.plan_expires_at = None
        db.session.commit()

    @staticmethod
    def get_time_until_midnight():
        """Calculates time remaining until midnight 12:00:00 AM renewal."""
        now = datetime.now()
        tomorrow_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_left = max(0, int((tomorrow_midnight - now).total_seconds()))
        hours, remainder = divmod(seconds_left, 3600)
        minutes, seconds = divmod(remainder, 60)
        return {
            'seconds_left': seconds_left,
            'countdown_str': f"{hours:02d}h {minutes:02d}m {seconds:02d}s",
            'renewal_time': "12:00 AM"
        }

    def to_dict(self):
        self.reset_quota_if_new_day()
        time_info = self.get_time_until_midnight()
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'plan_tier': self.plan_tier,
            'plan_name': PLAN_NAMES.get(self.plan_tier, self.plan_tier.capitalize()),
            'daily_limit': self.daily_limit,
            'checks_today': self.checks_today,
            'remaining_checks': self.get_remaining_checks(),
            'total_scans': self.total_scans,
            'is_active': self.is_active,
            'is_admin': self.is_admin(),
            'is_paid': self.is_paid(),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'plan_expires_at': self.plan_expires_at.strftime('%Y-%m-%d') if self.plan_expires_at else 'Lifetime / N/A',
            'reset_countdown': time_info['countdown_str'],
            'reset_seconds': time_info['seconds_left']
        }


class ScanLog(db.Model):
    __tablename__ = 'scan_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False, index=True)
    resolved_ip = db.Column(db.String(120), nullable=True)
    scan_type = db.Column(db.String(50), nullable=False) # 'metadata', 'dns', 'ping', 'ports', 'ftp_anonymous', 'nmap'
    parameters = db.Column(db.Text, nullable=True)       # JSON string (e.g. port)
    status = db.Column(db.String(20), default='SUCCESS') # SUCCESS, ERROR, VULNERABLE, SECURE
    result_summary = db.Column(db.Text, nullable=True)
    full_output = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'Unknown',
            'target': self.target,
            'resolved_ip': self.resolved_ip or 'N/A',
            'scan_type': self.scan_type,
            'parameters': self.parameters,
            'status': self.status,
            'result_summary': self.result_summary,
            'full_output': self.full_output,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
