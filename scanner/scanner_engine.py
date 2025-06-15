import requests
import re
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url.strip()
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'http://' + self.target_url
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.timeout = 10
        
    def _make_request(self, url, method='GET', data=None, params=None):
        """Make HTTP request with error handling"""
        try:
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, params=params, timeout=self.timeout, verify=False)
            else:
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            return response
        except requests.exceptions.Timeout:
            logging.warning(f"Request timeout for {url}")
            return None
        except requests.exceptions.ConnectionError:
            logging.warning(f"Connection error for {url}")
            return None
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {url}: {str(e)}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error for {url}: {str(e)}")
            return None
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "1'; DROP TABLE users--",
            "' OR 1=1#"
        ]
        
        try:
            # First, get the original response
            original_response = self._make_request(self.target_url)
            if not original_response:
                return None
            
            original_length = len(original_response.content)
            
            # Test with payloads
            for payload in payloads:
                # Test in URL parameters
                test_url = f"{self.target_url}?id={payload}&search={payload}"
                response = self._make_request(test_url)
                
                if response:
                    # Check for SQL error messages
                    error_patterns = [
                        r"mysql_fetch_array\(\)",
                        r"ORA-\d{5}",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"PostgreSQL.*ERROR",
                        r"Warning.*mysql_.*",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"SQL syntax.*MySQL",
                        r"Warning.*\Wmysqli?_"
                    ]
                    
                    content = response.text.lower()
                    for pattern in error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return {
                                'vulnerability': 'SQL Injection',
                                'severity': 'High',
                                'description': f'SQL injection vulnerability detected using payload: {payload}',
                                'affected_parameter': 'URL parameters',
                                'recommendation': 'Use parameterized queries and input validation'
                            }
                    
                    # Check for significant response length differences
                    if abs(len(response.content) - original_length) > 1000:
                        return {
                            'vulnerability': 'Potential SQL Injection',
                            'severity': 'Medium',
                            'description': f'Response length significantly different with payload: {payload}',
                            'affected_parameter': 'URL parameters',
                            'recommendation': 'Investigate further and use parameterized queries'
                        }
            
            return None
            
        except Exception as e:
            logging.error(f"SQL injection test failed: {str(e)}")
            return None
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ]
        
        try:
            for payload in payloads:
                # Test reflected XSS in URL parameters
                test_url = f"{self.target_url}?search={payload}&q={payload}"
                response = self._make_request(test_url)
                
                if response and payload in response.text:
                    return {
                        'vulnerability': 'Reflected XSS',
                        'severity': 'High',
                        'description': f'Reflected XSS vulnerability detected with payload: {payload}',
                        'affected_parameter': 'URL parameters',
                        'recommendation': 'Implement proper input validation and output encoding'
                    }
                
                # Test for forms and POST XSS
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        action = form.get('action', '')
                        if action:
                            form_url = urljoin(self.target_url, action)
                        else:
                            form_url = self.target_url
                        
                        # Build form data
                        form_data = {}
                        inputs = form.find_all(['input', 'textarea'])
                        for input_field in inputs:
                            name = input_field.get('name')
                            if name and input_field.get('type') != 'submit':
                                form_data[name] = payload
                        
                        if form_data:
                            post_response = self._make_request(form_url, method='POST', data=form_data)
                            if post_response and payload in post_response.text:
                                return {
                                    'vulnerability': 'Stored/Reflected XSS',
                                    'severity': 'High',
                                    'description': f'XSS vulnerability detected in form with payload: {payload}',
                                    'affected_parameter': 'Form inputs',
                                    'recommendation': 'Implement proper input validation and output encoding'
                                }
                
                except Exception as e:
                    logging.warning(f"Form XSS test failed: {str(e)}")
                    continue
            
            return None
            
        except Exception as e:
            logging.error(f"XSS test failed: {str(e)}")
            return None
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        try:
            response = self._make_request(self.target_url)
            if not response:
                return None
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            csrf_protected = False
            for form in forms:
                # Check for CSRF tokens
                csrf_inputs = form.find_all('input', {'name': re.compile(r'.*csrf.*|.*token.*', re.I)})
                if csrf_inputs:
                    csrf_protected = True
                    break
            
            if not csrf_protected and forms:
                return {
                    'vulnerability': 'Missing CSRF Protection',
                    'severity': 'Medium',
                    'description': 'Forms detected without CSRF protection tokens',
                    'affected_parameter': 'All forms',
                    'recommendation': 'Implement CSRF tokens in all state-changing forms'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"CSRF test failed: {str(e)}")
            return None
    
    def test_command_injection(self):
        """Test for command injection vulnerabilities"""
        payloads = [
            "; ls",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)"
        ]
        
        try:
            for payload in payloads:
                test_url = f"{self.target_url}?cmd={payload}&exec={payload}"
                response = self._make_request(test_url)
                
                if response:
                    # Check for command output patterns
                    command_patterns = [
                        r"uid=\d+\(.*\)",
                        r"root:.*:0:0:",
                        r"bin:.*:1:1:",
                        r"total \d+",
                        r"drwxr-xr-x"
                    ]
                    
                    for pattern in command_patterns:
                        if re.search(pattern, response.text):
                            return {
                                'vulnerability': 'Command Injection',
                                'severity': 'Critical',
                                'description': f'Command injection detected with payload: {payload}',
                                'affected_parameter': 'URL parameters',
                                'recommendation': 'Never execute user input as system commands. Use input validation and sanitization'
                            }
            
            return None
            
        except Exception as e:
            logging.error(f"Command injection test failed: {str(e)}")
            return None
    
    def test_insecure_headers(self):
        """Test for insecure HTTP headers"""
        try:
            response = self._make_request(self.target_url)
            if not response:
                return None
            
            headers = response.headers
            issues = []
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Strict-Transport-Security': 'Missing HSTS header (HTTPS only)',
                'Content-Security-Policy': 'Missing Content Security Policy header'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    issues.append(description)
            
            # Check for information disclosure
            if 'Server' in headers:
                server_header = headers['Server']
                if any(info in server_header.lower() for info in ['apache', 'nginx', 'iis', 'php']):
                    issues.append(f'Server information disclosure: {server_header}')
            
            if 'X-Powered-By' in headers:
                issues.append(f'Technology disclosure: {headers["X-Powered-By"]}')
            
            if issues:
                return {
                    'vulnerability': 'Insecure Headers',
                    'severity': 'Low',
                    'description': '; '.join(issues),
                    'affected_parameter': 'HTTP Headers',
                    'recommendation': 'Implement proper security headers and remove information disclosure headers'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"Header security test failed: {str(e)}")
            return None
    
    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        try:
            for payload in payloads:
                test_url = f"{self.target_url}?file={payload}&path={payload}"
                response = self._make_request(test_url)
                
                if response:
                    # Check for file content patterns
                    file_patterns = [
                        r"root:.*:0:0:",
                        r"# Copyright.*Microsoft Corp",
                        r"localhost",
                        r"# This file contains the mappings"
                    ]
                    
                    for pattern in file_patterns:
                        if re.search(pattern, response.text):
                            return {
                                'vulnerability': 'Directory Traversal',
                                'severity': 'High',
                                'description': f'Directory traversal vulnerability detected with payload: {payload}',
                                'affected_parameter': 'File parameters',
                                'recommendation': 'Implement proper input validation and restrict file access'
                            }
            
            return None
            
        except Exception as e:
            logging.error(f"Directory traversal test failed: {str(e)}")
            return None
    
    def test_file_upload(self):
        """Test for insecure file upload vulnerabilities"""
        try:
            response = self._make_request(self.target_url)
            if not response:
                return None
            
            soup = BeautifulSoup(response.text, 'html.parser')
            file_inputs = soup.find_all('input', {'type': 'file'})
            
            if file_inputs:
                return {
                    'vulnerability': 'File Upload Found',
                    'severity': 'Medium',
                    'description': 'File upload functionality detected - requires manual testing',
                    'affected_parameter': 'File upload form',
                    'recommendation': 'Implement file type validation, size limits, and scan uploaded files'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"File upload test failed: {str(e)}")
            return None
    
    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        try:
            disclosure_paths = [
                '/.env',
                '/config.php',
                '/phpinfo.php',
                '/.git/config',
                '/robots.txt',
                '/admin/config.php',
                '/wp-config.php',
                '/.htaccess'
            ]
            
            for path in disclosure_paths:
                test_url = urljoin(self.target_url, path)
                response = self._make_request(test_url)
                
                if response and response.status_code == 200:
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['password', 'secret', 'key', 'token', 'database']):
                        return {
                            'vulnerability': 'Information Disclosure',
                            'severity': 'Medium',
                            'description': f'Sensitive information exposed at {path}',
                            'affected_parameter': path,
                            'recommendation': 'Restrict access to sensitive files and implement proper access controls'
                        }
            
            return None
            
        except Exception as e:
            logging.error(f"Information disclosure test failed: {str(e)}")
            return None
    
    def test_ssl_tls_security(self):
        """Test for SSL/TLS security issues"""
        try:
            from urllib.parse import urlparse
            
            parsed_url = urlparse(self.target_url)
            
            if parsed_url.scheme != 'https':
                return {
                    'vulnerability': 'Insecure Protocol',
                    'severity': 'Medium',
                    'description': 'Website does not use HTTPS encryption',
                    'affected_parameter': 'Protocol',
                    'recommendation': 'Implement SSL/TLS encryption for all communications'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"SSL/TLS test failed: {str(e)}")
            return None
    
    def test_session_management(self):
        """Test for session management vulnerabilities"""
        try:
            response = self._make_request(self.target_url)
            if not response:
                return None
            
            issues = []
            
            # Check Set-Cookie headers
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            if set_cookie_headers:
                if 'Secure' not in set_cookie_headers:
                    issues.append('Cookies not marked as Secure')
                if 'HttpOnly' not in set_cookie_headers:
                    issues.append('Cookies not marked as HttpOnly')
                if 'SameSite' not in set_cookie_headers:
                    issues.append('Cookies missing SameSite attribute')
            
            if issues:
                return {
                    'vulnerability': 'Insecure Session Management',
                    'severity': 'Medium',
                    'description': '; '.join(issues),
                    'affected_parameter': 'Session Cookies',
                    'recommendation': 'Configure secure session cookie attributes (Secure, HttpOnly, SameSite)'
                }
            
            return None
            
        except Exception as e:
            logging.error(f"Session management test failed: {str(e)}")
            return None
