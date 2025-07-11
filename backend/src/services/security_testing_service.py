import requests
import nmap
import socket
import ssl
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import subprocess
import time

class SecurityTestingService:
    def __init__(self):
        self.vulnerabilities = []
        self.security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
    
    def run_security_test(self, url):
        """Run comprehensive security testing - alias for run_security_scan"""
        return self.run_security_scan(url)
    
    def run_security_scan(self, url):
        """Run comprehensive security testing"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            results = {
                'url': url,
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'security_tests': {}
            }
            
            # SSL/TLS Testing
            results['security_tests']['ssl_tls'] = self._test_ssl_tls(domain)
            
            # Security Headers Testing
            results['security_tests']['security_headers'] = self._test_security_headers(url)
            
            # Common Vulnerabilities Testing
            results['security_tests']['vulnerabilities'] = self._test_common_vulnerabilities(url)
            
            # Port Scanning (limited)
            results['security_tests']['port_scan'] = self._test_open_ports(domain)
            
            # Directory Traversal Testing
            results['security_tests']['directory_traversal'] = self._test_directory_traversal(url)
            
            # SQL Injection Testing (basic)
            results['security_tests']['sql_injection'] = self._test_sql_injection(url)
            
            # XSS Testing (basic)
            results['security_tests']['xss'] = self._test_xss_vulnerabilities(url)
            
            # Information Disclosure Testing
            results['security_tests']['info_disclosure'] = self._test_information_disclosure(url)
            
            # Calculate overall security score
            results['security_score'] = self._calculate_security_score(results['security_tests'])
            results['risk_level'] = self._determine_risk_level(results['security_score'])
            
            return results
            
        except Exception as e:
            return {'error': f'Security testing failed: {str(e)}'}
    
    def _test_ssl_tls(self, domain):
        """Test SSL/TLS configuration"""
        try:
            # Test SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    # Check for weak cipher suites (basic check)
                    cipher = ssock.cipher()
                    
                    issues = []
                    if days_until_expiry < 30:
                        issues.append(f'Certificate expires in {days_until_expiry} days')
                    
                    if cipher and cipher[1] < 128:
                        issues.append(f'Weak cipher strength: {cipher[1]} bits')
                    
                    return {
                        'status': 'passed' if not issues else 'warning',
                        'certificate_valid': True,
                        'days_until_expiry': days_until_expiry,
                        'issuer': cert.get('issuer', []),
                        'subject': cert.get('subject', []),
                        'cipher_suite': cipher,
                        'issues': issues
                    }
        except ssl.SSLError as e:
            return {
                'status': 'failed',
                'certificate_valid': False,
                'error': f'SSL Error: {str(e)}'
            }
        except Exception as e:
            return {
                'status': 'failed',
                'error': f'SSL test failed: {str(e)}'
            }
    
    def _test_security_headers(self, url):
        """Test for security headers"""
        try:
            response = requests.get(url, timeout=30)
            headers = response.headers
            
            missing_headers = []
            present_headers = []
            header_issues = []
            
            for header in self.security_headers:
                if header in headers:
                    present_headers.append({
                        'name': header,
                        'value': headers[header]
                    })
                else:
                    missing_headers.append(header)
            
            # Check specific header configurations
            if 'Strict-Transport-Security' in headers:
                hsts_value = headers['Strict-Transport-Security']
                if 'max-age' not in hsts_value:
                    header_issues.append('HSTS header missing max-age directive')
                elif 'max-age=0' in hsts_value:
                    header_issues.append('HSTS max-age is set to 0')
            
            if 'Content-Security-Policy' in headers:
                csp_value = headers['Content-Security-Policy']
                if 'unsafe-inline' in csp_value:
                    header_issues.append('CSP allows unsafe-inline')
                if 'unsafe-eval' in csp_value:
                    header_issues.append('CSP allows unsafe-eval')
            
            security_score = max(0, 100 - (len(missing_headers) * 15) - (len(header_issues) * 10))
            
            return {
                'status': 'passed' if security_score > 80 else 'warning' if security_score > 60 else 'failed',
                'security_score': security_score,
                'present_headers': present_headers,
                'missing_headers': missing_headers,
                'header_issues': header_issues
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_common_vulnerabilities(self, url):
        """Test for common web vulnerabilities"""
        try:
            vulnerabilities = []
            
            # Test for clickjacking
            response = requests.get(url, timeout=30)
            if 'X-Frame-Options' not in response.headers and 'Content-Security-Policy' not in response.headers:
                vulnerabilities.append({
                    'type': 'Clickjacking',
                    'severity': 'Medium',
                    'description': 'Missing X-Frame-Options and CSP frame-ancestors directive'
                })
            
            # Test for MIME sniffing
            if 'X-Content-Type-Options' not in response.headers:
                vulnerabilities.append({
                    'type': 'MIME Sniffing',
                    'severity': 'Low',
                    'description': 'Missing X-Content-Type-Options header'
                })
            
            # Test for mixed content (if HTTPS)
            if url.startswith('https://'):
                soup = BeautifulSoup(response.content, 'html.parser')
                http_resources = []
                
                # Check for HTTP resources in HTTPS page
                for tag in soup.find_all(['img', 'script', 'link']):
                    src = tag.get('src') or tag.get('href')
                    if src and src.startswith('http://'):
                        http_resources.append(src)
                
                if http_resources:
                    vulnerabilities.append({
                        'type': 'Mixed Content',
                        'severity': 'Medium',
                        'description': f'Found {len(http_resources)} HTTP resources in HTTPS page',
                        'resources': http_resources[:5]  # Limit to first 5
                    })
            
            return {
                'status': 'passed' if not vulnerabilities else 'warning',
                'vulnerabilities_count': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_open_ports(self, domain):
        """Test for open ports (limited scan)"""
        try:
            nm = nmap.PortScanner()
            
            # Scan common ports only to avoid being too aggressive
            common_ports = '22,23,25,53,80,110,143,443,993,995,8080,8443'
            
            # Quick scan with timeout
            result = nm.scan(domain, common_ports, arguments='-sS -T4 --max-retries 1 --host-timeout 30s')
            
            if domain in result['scan']:
                host_info = result['scan'][domain]
                open_ports = []
                
                if 'tcp' in host_info:
                    for port, info in host_info['tcp'].items():
                        if info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': info.get('name', 'unknown'),
                                'version': info.get('version', 'unknown')
                            })
                
                # Assess risk based on open ports
                risky_ports = [22, 23, 25, 110, 143]  # SSH, Telnet, SMTP, POP3, IMAP
                risky_open = [p for p in open_ports if p['port'] in risky_ports]
                
                return {
                    'status': 'warning' if risky_open else 'passed',
                    'open_ports': open_ports,
                    'risky_ports': risky_open,
                    'total_scanned': len(common_ports.split(','))
                }
            else:
                return {'status': 'failed', 'error': 'Host not reachable for port scan'}
                
        except Exception as e:
            return {'status': 'failed', 'error': f'Port scan failed: {str(e)}'}
    
    def _test_directory_traversal(self, url):
        """Test for directory traversal vulnerabilities"""
        try:
            base_url = url.rstrip('/')
            traversal_payloads = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
            ]
            
            vulnerabilities = []
            
            for payload in traversal_payloads:
                test_url = f"{base_url}/{payload}"
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for signs of successful directory traversal
                    if response.status_code == 200:
                        content = response.text.lower()
                        if any(indicator in content for indicator in ['root:', 'bin:', 'daemon:', '[drivers]']):
                            vulnerabilities.append({
                                'type': 'Directory Traversal',
                                'severity': 'High',
                                'payload': payload,
                                'url': test_url
                            })
                            break  # Found one, no need to test more
                            
                except requests.RequestException:
                    continue
            
            return {
                'status': 'failed' if vulnerabilities else 'passed',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(traversal_payloads)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities (basic)"""
        try:
            # Get the page and look for forms
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            if not forms:
                return {'status': 'skipped', 'message': 'No forms found for SQL injection testing'}
            
            sql_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users;--",
                "' UNION SELECT NULL--"
            ]
            
            vulnerabilities = []
            
            for form in forms[:3]:  # Test first 3 forms only
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                # Build form URL
                if action.startswith('http'):
                    form_url = action
                elif action.startswith('/'):
                    parsed = urlparse(url)
                    form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    form_url = urljoin(url, action)
                
                # Get form inputs
                inputs = form.find_all('input')
                form_data = {}
                
                for input_elem in inputs:
                    name = input_elem.get('name')
                    if name and input_elem.get('type') not in ['submit', 'button']:
                        form_data[name] = 'test'
                
                # Test SQL injection payloads
                for payload in sql_payloads:
                    test_data = form_data.copy()
                    if test_data:
                        # Inject payload into first text field
                        first_field = list(test_data.keys())[0]
                        test_data[first_field] = payload
                        
                        try:
                            if method == 'POST':
                                test_response = requests.post(form_url, data=test_data, timeout=10)
                            else:
                                test_response = requests.get(form_url, params=test_data, timeout=10)
                            
                            # Check for SQL error messages
                            error_indicators = [
                                'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                                'sqlite_', 'postgresql', 'warning: mysql'
                            ]
                            
                            if any(indicator in test_response.text.lower() for indicator in error_indicators):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'form_url': form_url,
                                    'payload': payload,
                                    'method': method
                                })
                                break  # Found vulnerability, move to next form
                                
                        except requests.RequestException:
                            continue
            
            return {
                'status': 'failed' if vulnerabilities else 'passed',
                'vulnerabilities': vulnerabilities,
                'forms_tested': len(forms)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_xss_vulnerabilities(self, url):
        """Test for XSS vulnerabilities (basic)"""
        try:
            # Get the page and look for forms and URL parameters
            response = requests.get(url, timeout=30)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "javascript:alert('XSS')",
                '<img src=x onerror=alert("XSS")>'
            ]
            
            vulnerabilities = []
            
            # Test URL parameters if any
            parsed_url = urlparse(url)
            if parsed_url.query:
                for payload in xss_payloads:
                    # Replace parameter values with XSS payload
                    test_url = url.replace(parsed_url.query.split('=')[1], payload)
                    try:
                        test_response = requests.get(test_url, timeout=10)
                        if payload in test_response.text:
                            vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'severity': 'High',
                                'location': 'URL Parameter',
                                'payload': payload
                            })
                            break
                    except requests.RequestException:
                        continue
            
            # Test forms
            forms = soup.find_all('form')
            for form in forms[:2]:  # Test first 2 forms only
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                # Build form URL
                if action.startswith('http'):
                    form_url = action
                elif action.startswith('/'):
                    parsed = urlparse(url)
                    form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
                else:
                    form_url = urljoin(url, action)
                
                # Get form inputs
                inputs = form.find_all('input')
                form_data = {}
                
                for input_elem in inputs:
                    name = input_elem.get('name')
                    if name and input_elem.get('type') not in ['submit', 'button']:
                        form_data[name] = 'test'
                
                # Test XSS payloads
                for payload in xss_payloads:
                    test_data = form_data.copy()
                    if test_data:
                        # Inject payload into first text field
                        first_field = list(test_data.keys())[0]
                        test_data[first_field] = payload
                        
                        try:
                            if method == 'POST':
                                test_response = requests.post(form_url, data=test_data, timeout=10)
                            else:
                                test_response = requests.get(form_url, params=test_data, timeout=10)
                            
                            # Check if payload is reflected in response
                            if payload in test_response.text:
                                vulnerabilities.append({
                                    'type': 'Reflected XSS',
                                    'severity': 'High',
                                    'location': 'Form Input',
                                    'form_url': form_url,
                                    'payload': payload
                                })
                                break
                                
                        except requests.RequestException:
                            continue
            
            return {
                'status': 'failed' if vulnerabilities else 'passed',
                'vulnerabilities': vulnerabilities,
                'payloads_tested': len(xss_payloads)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _test_information_disclosure(self, url):
        """Test for information disclosure"""
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            disclosure_tests = [
                '/robots.txt',
                '/.git/config',
                '/.env',
                '/config.php',
                '/phpinfo.php',
                '/server-status',
                '/server-info'
            ]
            
            findings = []
            
            for test_path in disclosure_tests:
                test_url = base_url + test_path
                try:
                    response = requests.get(test_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for sensitive information
                        if test_path == '/robots.txt':
                            if 'disallow:' in content:
                                findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': 'Low',
                                    'file': test_path,
                                    'description': 'robots.txt reveals directory structure'
                                })
                        elif test_path == '/.git/config':
                            if '[core]' in content or 'repositoryformatversion' in content:
                                findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': 'High',
                                    'file': test_path,
                                    'description': 'Git configuration file exposed'
                                })
                        elif test_path == '/.env':
                            if any(keyword in content for keyword in ['password', 'secret', 'key', 'token']):
                                findings.append({
                                    'type': 'Information Disclosure',
                                    'severity': 'Critical',
                                    'file': test_path,
                                    'description': 'Environment file with secrets exposed'
                                })
                        elif 'phpinfo()' in content or 'php version' in content:
                            findings.append({
                                'type': 'Information Disclosure',
                                'severity': 'Medium',
                                'file': test_path,
                                'description': 'PHP information disclosure'
                            })
                            
                except requests.RequestException:
                    continue
            
            return {
                'status': 'failed' if any(f['severity'] in ['High', 'Critical'] for f in findings) else 'warning' if findings else 'passed',
                'findings': findings,
                'tests_performed': len(disclosure_tests)
            }
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _calculate_security_score(self, security_tests):
        """Calculate overall security score"""
        scores = []
        weights = {
            'ssl_tls': 0.2,
            'security_headers': 0.2,
            'vulnerabilities': 0.25,
            'port_scan': 0.1,
            'directory_traversal': 0.05,
            'sql_injection': 0.1,
            'xss': 0.05,
            'info_disclosure': 0.05
        }
        
        for test_name, test_result in security_tests.items():
            if isinstance(test_result, dict) and 'status' in test_result:
                weight = weights.get(test_name, 0.1)
                
                if test_result['status'] == 'passed':
                    scores.append(100 * weight)
                elif test_result['status'] == 'warning':
                    scores.append(70 * weight)
                elif test_result['status'] == 'failed':
                    scores.append(30 * weight)
                # Skip 'skipped' tests
        
        return round(sum(scores)) if scores else 0
    
    def _determine_risk_level(self, security_score):
        """Determine risk level based on security score"""
        if security_score >= 80:
            return 'Low'
        elif security_score >= 60:
            return 'Medium'
        elif security_score >= 40:
            return 'High'
        else:
            return 'Critical'

