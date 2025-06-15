import re
import json
import logging
import pandas as pd
from datetime import datetime
from collections import Counter, defaultdict
import ipaddress

class LogAnalyzer:
    def __init__(self, filepath, log_type='auto'):
        self.filepath = filepath
        self.log_type = log_type
        self.entries = []
        self.suspicious_patterns = {
            'sql_injection': [
                r"union.*select",
                r"drop.*table",
                r"'.*or.*'.*=.*'",
                r"admin'--",
                r"1=1"
            ],
            'xss': [
                r"<script",
                r"javascript:",
                r"alert\(",
                r"onerror=",
                r"onload="
            ],
            'command_injection': [
                r";.*ls",
                r"\|.*whoami",
                r"&&.*cat",
                r"`.*id.*`",
                r"\$\(.*\)"
            ],
            'directory_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"etc/passwd",
                r"windows/system32"
            ]
        }
        
    def detect_log_type(self, sample_lines):
        """Auto-detect log format"""
        apache_pattern = r'\d+\.\d+\.\d+\.\d+ - - \['
        nginx_pattern = r'\d+\.\d+\.\d+\.\d+ - \w+ \['
        json_pattern = r'^\s*\{'
        
        for line in sample_lines:
            if re.match(apache_pattern, line):
                return 'apache'
            elif re.match(nginx_pattern, line):
                return 'nginx'
            elif re.match(json_pattern, line):
                return 'json'
        
        return 'generic'
    
    def parse_apache_log(self, line):
        """Parse Apache access log format"""
        pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'request': match.group(3),
                'status_code': int(match.group(4)),
                'size': int(match.group(5)) if match.group(5) != '-' else 0,
                'referer': match.group(6),
                'user_agent': match.group(7)
            }
        return None
    
    def parse_nginx_log(self, line):
        """Parse Nginx access log format"""
        pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if match:
            return {
                'ip': match.group(1),
                'user': match.group(2),
                'timestamp': match.group(3),
                'request': match.group(4),
                'status_code': int(match.group(5)),
                'size': int(match.group(6)) if match.group(6) != '-' else 0,
                'referer': match.group(7),
                'user_agent': match.group(8)
            }
        return None
    
    def parse_json_log(self, line):
        """Parse JSON log format"""
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None
    
    def parse_generic_log(self, line):
        """Parse generic log format - extract IP and basic info"""
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ip_match = re.search(ip_pattern, line)
        
        if ip_match:
            return {
                'ip': ip_match.group(1),
                'raw_line': line,
                'timestamp': None
            }
        return None
    
    def is_suspicious_ip(self, ip):
        """Check if IP is suspicious"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IPs (less suspicious)
            if ip_obj.is_private:
                return False
            
            # Check for known suspicious patterns
            suspicious_ranges = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]
            
            # This is a simplified check - in production, you'd use IP reputation APIs
            return True  # For demo, consider all public IPs potentially suspicious
            
        except ValueError:
            return False
    
    def detect_attack_patterns(self, entry):
        """Detect various attack patterns in log entry"""
        attacks = []
        
        # Get request string
        request = entry.get('request', '') or entry.get('raw_line', '')
        request_lower = request.lower()
        
        # Check for different attack types
        for attack_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, request_lower, re.IGNORECASE):
                    attacks.append(attack_type)
                    break
        
        return attacks
    
    def detect_brute_force(self, entries):
        """Detect brute force attempts"""
        failed_logins = 0
        ip_failures = defaultdict(int)
        
        for entry in entries:
            status_code = entry.get('status_code', 200)
            request = entry.get('request', '') or entry.get('raw_line', '')
            
            # Check for failed login patterns
            if (status_code in [401, 403] or 
                'login' in request.lower() or 
                'admin' in request.lower() or
                'wp-admin' in request.lower()):
                failed_logins += 1
                ip = entry.get('ip')
                if ip:
                    ip_failures[ip] += 1
        
        return failed_logins, dict(ip_failures)
    
    def detect_port_scans(self, entries):
        """Detect port scanning attempts"""
        ip_requests = defaultdict(set)
        
        for entry in entries:
            ip = entry.get('ip')
            request = entry.get('request', '') or entry.get('raw_line', '')
            
            if ip and request:
                # Extract path from request
                try:
                    path = request.split()[1] if len(request.split()) > 1 else '/'
                    ip_requests[ip].add(path)
                except:
                    continue
        
        # Consider it a port scan if an IP requests many different paths
        port_scans = 0
        for ip, paths in ip_requests.items():
            if len(paths) > 10:  # Threshold for port scan detection
                port_scans += 1
        
        return port_scans
    
    def detect_dos_attempts(self, entries):
        """Detect DoS attack attempts"""
        ip_counts = defaultdict(int)
        
        for entry in entries:
            ip = entry.get('ip')
            if ip:
                ip_counts[ip] += 1
        
        # Consider it DoS if an IP makes more than 100 requests
        dos_attempts = 0
        for ip, count in ip_counts.items():
            if count > 100:
                dos_attempts += 1
        
        return dos_attempts
    
    def analyze(self):
        """Main analysis function"""
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            if not lines:
                return None
            
            # Auto-detect log type if not specified
            if self.log_type == 'auto':
                self.log_type = self.detect_log_type(lines[:10])
            
            # Parse log entries
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                entry = None
                if self.log_type == 'apache':
                    entry = self.parse_apache_log(line)
                elif self.log_type == 'nginx':
                    entry = self.parse_nginx_log(line)
                elif self.log_type == 'json':
                    entry = self.parse_json_log(line)
                else:
                    entry = self.parse_generic_log(line)
                
                if entry:
                    # Add attack pattern detection
                    entry['attacks'] = self.detect_attack_patterns(entry)
                    self.entries.append(entry)
            
            if not self.entries:
                return None
            
            # Perform analysis
            total_entries = len(self.entries)
            
            # Get IP statistics
            ip_counter = Counter(entry.get('ip') for entry in self.entries if entry.get('ip'))
            top_ips = [{'ip': ip, 'count': count} for ip, count in ip_counter.most_common(10)]
            
            # Find suspicious IPs
            suspicious_ips = []
            for entry in self.entries:
                ip = entry.get('ip')
                if ip and (self.is_suspicious_ip(ip) or entry.get('attacks')):
                    if ip not in [s['ip'] for s in suspicious_ips]:
                        suspicious_ips.append({
                            'ip': ip,
                            'attacks': entry.get('attacks', []),
                            'count': ip_counter.get(ip, 0)
                        })
            
            # Detect attack patterns
            failed_logins, brute_force_ips = self.detect_brute_force(self.entries)
            port_scans = self.detect_port_scans(self.entries)
            dos_attempts = self.detect_dos_attempts(self.entries)
            
            return {
                'log_type': self.log_type,
                'total_entries': total_entries,
                'suspicious_ips': suspicious_ips[:20],  # Limit to top 20
                'failed_logins': failed_logins,
                'port_scans': port_scans,
                'dos_attempts': dos_attempts,
                'top_ips': top_ips,
                'brute_force_ips': dict(list(brute_force_ips.items())[:10])
            }
            
        except Exception as e:
            logging.error(f"Log analysis failed: {str(e)}")
            return None
