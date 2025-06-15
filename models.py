from datetime import datetime
from app import db

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(100), nullable=False)
    vulnerability = db.Column(db.String(200))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    affected_parameter = db.Column(db.String(200))
    recommendation = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'vulnerability': self.vulnerability,
            'severity': self.severity,
            'description': self.description,
            'affected_parameter': self.affected_parameter,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class LogAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    log_type = db.Column(db.String(100), nullable=False)
    total_entries = db.Column(db.Integer, default=0)
    suspicious_ips = db.Column(db.Text)  # JSON string
    failed_logins = db.Column(db.Integer, default=0)
    port_scans = db.Column(db.Integer, default=0)
    dos_attempts = db.Column(db.Integer, default=0)
    top_ips = db.Column(db.Text)  # JSON string
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'log_type': self.log_type,
            'total_entries': self.total_entries,
            'suspicious_ips': self.suspicious_ips,
            'failed_logins': self.failed_logins,
            'port_scans': self.port_scans,
            'dos_attempts': self.dos_attempts,
            'top_ips': self.top_ips,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
