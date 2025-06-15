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
    
    def __init__(self, target_url, scan_type, vulnerability=None, severity=None, 
                 description=None, affected_parameter=None, recommendation=None):
        self.target_url = target_url
        self.scan_type = scan_type
        self.vulnerability = vulnerability
        self.severity = severity
        self.description = description
        self.affected_parameter = affected_parameter
        self.recommendation = recommendation
    
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
    
    def __init__(self, filename, log_type, total_entries=0, suspicious_ips=None,
                 failed_logins=0, port_scans=0, dos_attempts=0, top_ips=None):
        self.filename = filename
        self.log_type = log_type
        self.total_entries = total_entries
        self.suspicious_ips = suspicious_ips
        self.failed_logins = failed_logins
        self.port_scans = port_scans
        self.dos_attempts = dos_attempts
        self.top_ips = top_ips
    
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
