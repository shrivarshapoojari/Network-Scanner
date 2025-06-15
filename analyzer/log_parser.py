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
        firewall_pattern = r'.+kernel:.+\[UFW\s+(BLOCK|ALLOW)\]'
        security_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\s+(IDS_ALERT|FIREWALL_|AUTH_FAIL|DDoS_ALERT)'
        
        for line in sample_lines:
            if re.match(apache_pattern, line):
                return 'apache'
            elif re.match(nginx_pattern, line):
                return 'nginx'
            elif re.match(json_pattern, line):
                return 'json'
            elif re.search(firewall_pattern, line):
                return 'firewall'
            elif re.search(security_pattern, line):
                return 'security'
        
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
    
    def parse_firewall_log(self, line):
        """Parse firewall log format (UFW)"""
        pattern = r'.+\[UFW\s+(BLOCK|ALLOW)\].+SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).+DPT=(\d+)'
        match = re.search(pattern, line)
        
        if match:
            action = match.group(1)
            src_ip = match.group(2)
            dst_ip = match.group(3)
            port = match.group(4)
            
            return {
                'ip': src_ip,
                'action': action,
                'destination_ip': dst_ip,
                'destination_port': int(port),
                'raw_line': line,
                'timestamp': None,
                'log_type': 'firewall'
            }
        return None
    
    def parse_security_log(self, line):
        """Parse security event log format"""
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+(\w+):\s+(.+?)(?:from\s+(\d+\.\d+\.\d+\.\d+))?'
        match = re.search(pattern, line)
        
        if match:
            timestamp = match.group(1)
            event_type = match.group(2)
            description = match.group(3)
            ip = match.group(4) if match.group(4) else None
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'event_type': event_type,
                'description': description,
                'raw_line': line,
                'log_type': 'security'
            }
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
        
        # Get request string or raw line
        request = entry.get('request', '') or entry.get('raw_line', '') or entry.get('description', '')
        request_lower = request.lower()
        
        # Check for different attack types
        for attack_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, request_lower, re.IGNORECASE):
                    attacks.append(attack_type)
                    break
        
        # Check for security event types
        event_type = entry.get('event_type', '')
        if event_type:
            if 'IDS_ALERT' in event_type:
                attacks.append('intrusion_detection')
            elif 'AUTH_FAIL' in event_type:
                attacks.append('authentication_failure')
            elif 'DDoS_ALERT' in event_type:
                attacks.append('ddos_attack')
            elif 'MALWARE_DETECTED' in event_type:
                attacks.append('malware')
        
        # Check firewall actions
        if entry.get('action') == 'BLOCK':
            attacks.append('blocked_connection')
        
        return attacks
    
    def detect_brute_force(self, entries):
        """Detect brute force attempts"""
        failed_logins = 0
        ip_failures = defaultdict(int)
        
        for entry in entries:
            status_code = entry.get('status_code', 200)
            request = entry.get('request', '') or entry.get('raw_line', '') or entry.get('description', '')
            event_type = entry.get('event_type', '')
            
            # Check for failed login patterns
            is_failed_login = False
            
            # HTTP-based failed logins
            if (status_code in [401, 403] or 
                'login' in request.lower() or 
                'admin' in request.lower() or
                'wp-admin' in request.lower()):
                is_failed_login = True
            
            # Security event-based failed logins
            elif 'AUTH_FAIL' in event_type or 'Failed' in request:
                is_failed_login = True
            
            # Firewall blocked authentication attempts
            elif entry.get('action') == 'BLOCK' and entry.get('destination_port') in [22, 23, 21, 3389]:
                is_failed_login = True
            
            if is_failed_login:
                failed_logins += 1
                ip = entry.get('ip')
                if ip:
                    ip_failures[ip] += 1
        
        return failed_logins, dict(ip_failures)
    
    def detect_port_scans(self, entries):
        """Detect port scanning attempts"""
        ip_requests = defaultdict(set)
        ip_ports = defaultdict(set)
        
        for entry in entries:
            ip = entry.get('ip')
            request = entry.get('request', '') or entry.get('raw_line', '') or entry.get('description', '')
            
            # For firewall logs, track destination ports
            if entry.get('log_type') == 'firewall' and entry.get('destination_port'):
                ip_ports[ip].add(entry.get('destination_port'))
            
            # For web logs, track different paths
            elif ip and request:
                try:
                    if 'scan' in request.lower() or 'port' in request.lower():
                        ip_requests[ip].add('port_scan_indicator')
                    path = request.split()[1] if len(request.split()) > 1 else '/'
                    ip_requests[ip].add(path)
                except:
                    continue
        
        # Count port scans
        port_scans = 0
        
        # Check for firewall-based port scans (multiple ports from same IP)
        for ip, ports in ip_ports.items():
            if len(ports) > 5:  # Threshold for port scan detection
                port_scans += 1
        
        # Check for web-based scans (many different paths)
        for ip, paths in ip_requests.items():
            if len(paths) > 10:  # Threshold for path scan detection
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
                elif self.log_type == 'firewall':
                    entry = self.parse_firewall_log(line)
                elif self.log_type == 'security':
                    entry = self.parse_security_log(line)
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
