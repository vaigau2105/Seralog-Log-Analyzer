#!/usr/bin/env python3

import os
import re
import json
import socket
import threading
import time
from datetime import datetime
from collections import Counter, defaultdict
from urllib.parse import urlparse
import subprocess
import sys
from werkzeug.utils import secure_filename

# Flask imports
try:
    from flask import Flask, render_template, render_template_string, request, jsonify, send_file, flash, redirect, url_for
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Optional dependencies
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class LogAnalyzerWeb:
    def __init__(self):
        if not FLASK_AVAILABLE:
            print("❌ Flask not installed. Install with: pip install flask")
            sys.exit(1)
            
        self.app = Flask(__name__)
        self.app.secret_key = 'log_analyzer_secret_key_2023'
        self.app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
        
        self.setup_directories()
        self.log_data = []
        self.analysis_results = {}
        self.setup_routes()
        
    def setup_directories(self):
        """Create necessary directories"""
        dirs = ['uploads', 'reports', 'static']
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)

    def parse_log_line(self, line, line_num):
        """Parse individual log line"""
        if not line or line.startswith('#'):
            return None
            
        # Apache/Nginx Common Log Format pattern
        apache_pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) (\S+)" (\d+) (\d+|-)'
        
        match = re.match(apache_pattern, line)
        if match:
            return {
                'line_number': line_num,
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'protocol': match.group(5),
                'status_code': int(match.group(6)),
                'size': match.group(7),
                'raw_line': line,
                'log_type': 'web'
            }
        
        # Generic pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        timestamp_pattern = r'\[(.*?)\]|\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\b'
        
        ip_match = re.search(ip_pattern, line)
        time_match = re.search(timestamp_pattern, line)
        
        return {
            'line_number': line_num,
            'ip': ip_match.group() if ip_match else 'unknown',
            'timestamp': time_match.group(1) if time_match and time_match.group(1) else 'unknown',
            'raw_line': line,
            'log_type': 'generic'
        }

    def analyze_logs(self, file_path):
        """Load and analyze log file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            self.log_data = []
            for line_num, line in enumerate(lines, 1):
                parsed_line = self.parse_log_line(line.strip(), line_num)
                if parsed_line:
                    self.log_data.append(parsed_line)
            
            # Perform all analyses
            self.analyze_ips()
            self.analyze_status_codes()
            self.detect_suspicious_activity()
            
            return True, f"Successfully analyzed {len(self.log_data)} log entries"
            
        except Exception as e:
            return False, f"Error analyzing file: {str(e)}"

    def analyze_ips(self):
        """Analyze IP addresses"""
        ip_counter = Counter()
        suspicious_ips = []
        
        for entry in self.log_data:
            ip = entry.get('ip', 'unknown')
            if ip != 'unknown':
                ip_counter[ip] += 1
        
        # Flag IPs with excessive requests
        for ip, count in ip_counter.most_common():
            if count > 50:  # Lower threshold for web demo
                suspicious_ips.append({'ip': ip, 'count': count, 'reason': 'High request volume'})
        
        self.analysis_results['ip_analysis'] = {
            'total_unique_ips': len(ip_counter),
            'top_ips': ip_counter.most_common(10),
            'suspicious_ips': suspicious_ips
        }

    def analyze_status_codes(self):
        """Analyze HTTP status codes"""
        status_counter = Counter()
        error_entries = []
        
        for entry in self.log_data:
            if 'status_code' in entry:
                status_counter[entry['status_code']] += 1
                if entry['status_code'] >= 400:
                    error_entries.append(entry)
        
        self.analysis_results['status_analysis'] = {
            'status_distribution': dict(status_counter),
            'total_errors': len(error_entries),
            'error_rate': len(error_entries) / len(self.log_data) * 100 if self.log_data else 0,
            'recent_errors': error_entries[-5:]
        }

    def detect_suspicious_activity(self):
        """Detect suspicious patterns"""
        suspicious_patterns = []
        attack_patterns = [
            (r'\.\./', 'Directory Traversal'),
            (r'<script', 'XSS Attempt'),
            (r'union.*select', 'SQL Injection'),
            (r'cmd\.exe|/bin/bash', 'Command Injection'),
            (r'wp-admin|wp-login', 'WordPress Attack'),
            (r'phpmyadmin', 'phpMyAdmin Attack')
        ]
        
        pattern_counter = Counter()
        
        for entry in self.log_data:
            raw_line = entry.get('raw_line', '').lower()
            for pattern, attack_type in attack_patterns:
                if re.search(pattern, raw_line, re.IGNORECASE):
                    pattern_counter[attack_type] += 1
                    suspicious_patterns.append({
                        'type': attack_type,
                        'ip': entry.get('ip', 'unknown'),
                        'line': entry.get('line_number', 0),
                        'timestamp': entry.get('timestamp', 'unknown')
                    })
        
        self.analysis_results['suspicious_activity'] = {
            'total_suspicious': len(suspicious_patterns),
            'attack_types': dict(pattern_counter),
            'recent_attacks': suspicious_patterns[-10:]
        }

    def check_password_strength(self, password):
        """Check password strength"""
        score = 0
        feedback = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password too short (minimum 8 characters)")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
            
        if re.search(r'[0-9]', password):
            score += 1
        else:
            feedback.append("Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("Avoid common patterns")
        
        if score >= 5:
            strength = "Strong"
            color = "success"
        elif score >= 3:
            strength = "Medium" 
            color = "warning"
        else:
            strength = "Weak"
            color = "danger"
        
        return {
            'strength': strength,
            'color': color,
            'score': max(0, score),
            'feedback': feedback
        }

    def port_scan(self, target, ports_str):
        """Basic port scanner"""
        if ports_str:
            try:
                ports = [int(p.strip()) for p in ports_str.split(',')]
            except ValueError:
                return {'error': 'Invalid port format'}
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        
        threads = []
        for port in ports[:20]:  # Limit to 20 ports for web demo
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        return {'open_ports': sorted(open_ports), 'total_scanned': len(ports[:20])}

    def create_sample_log(self):
        """Create sample log file"""
        sample_log = """127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
192.168.1.100 - - [10/Oct/2023:13:55:37 +0000] "POST /login.php HTTP/1.1" 200 1245
10.0.0.1 - - [10/Oct/2023:13:55:38 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 404 162
203.0.113.0 - - [10/Oct/2023:13:55:39 +0000] "GET /wp-admin/admin-ajax.php HTTP/1.1" 200 0
203.0.113.0 - - [10/Oct/2023:13:55:40 +0000] "POST /wp-login.php HTTP/1.1" 302 0
192.168.1.50 - - [10/Oct/2023:13:55:41 +0000] "GET /search?q=<script>alert('xss')</script> HTTP/1.1" 200 5420
10.0.0.2 - - [10/Oct/2023:13:55:42 +0000] "GET /index.php?id=1' UNION SELECT * FROM users-- HTTP/1.1" 500 0
127.0.0.1 - - [10/Oct/2023:13:55:43 +0000] "GET /favicon.ico HTTP/1.1" 404 209
192.168.1.100 - - [10/Oct/2023:13:55:44 +0000] "GET /dashboard HTTP/1.1" 200 3421
203.0.113.0 - - [10/Oct/2023:13:55:45 +0000] "GET /wp-admin/ HTTP/1.1" 401 1234
203.0.113.0 - - [10/Oct/2023:13:55:46 +0000] "GET /wp-admin/ HTTP/1.1" 401 1234
203.0.113.0 - - [10/Oct/2023:13:55:47 +0000] "GET /wp-admin/ HTTP/1.1" 401 1234
203.0.113.0 - - [10/Oct/2023:13:55:48 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162
192.168.1.75 - - [10/Oct/2023:13:55:49 +0000] "GET /cmd.exe HTTP/1.1" 404 162
10.0.0.5 - - [10/Oct/2023:13:55:50 +0000] "GET /index.html HTTP/1.1" 200 2326"""
        
        sample_file = "uploads/sample_access.log"
        with open(sample_file, 'w') as f:
            f.write(sample_log)
        return sample_file

    def setup_routes(self):
        """Setup Flask routes"""
        
        # Main template
        main_template = '''
        '''

        @self.app.route('/')
        def index():
            # --- CHANGE THIS LINE ---
            return render_template('index.html')

        @self.app.route('/upload', methods=['POST'])
        def upload_file():
            try:
                if 'file' not in request.files:
                    return jsonify({'success': False, 'message': 'No file uploaded'})
                
                file = request.files['file']
                if file.filename == '':
                    return jsonify({'success': False, 'message': 'No file selected'})
                
                filename = secure_filename(file.filename)
                file_path = os.path.join('uploads', filename)
                file.save(file_path)
                
                success, message = self.analyze_logs(file_path)
                
                if success:
                    results = {
                        'total_entries': len(self.log_data),
                        'ip_analysis': self.analysis_results.get('ip_analysis'),
                        'status_analysis': self.analysis_results.get('status_analysis'),
                        'suspicious_activity': self.analysis_results.get('suspicious_activity')
                    }
                    return jsonify({'success': True, 'message': message, 'results': results})
                else:
                    return jsonify({'success': False, 'message': message})
                    
            except Exception as e:
                return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

        @self.app.route('/sample')
        def sample_analysis():
            try:
                sample_file = self.create_sample_log()
                success, message = self.analyze_logs(sample_file)
                
                if success:
                    results = {
                        'total_entries': len(self.log_data),
                        'ip_analysis': self.analysis_results.get('ip_analysis'),
                        'status_analysis': self.analysis_results.get('status_analysis'),
                        'suspicious_activity': self.analysis_results.get('suspicious_activity')
                    }
                    return jsonify({'success': True, 'message': message, 'results': results})
                else:
                    return jsonify({'success': False, 'message': message})
                    
            except Exception as e:
                return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

        @self.app.route('/password', methods=['POST'])
        def check_password():
            try:
                data = request.get_json()
                password = data.get('password', '')
                result = self.check_password_strength(password)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': f'Server error: {str(e)}'})

        @self.app.route('/portscan', methods=['POST'])
        def port_scan_route():
            try:
                data = request.get_json()
                target = data.get('target', '')
                ports_str = data.get('ports', '')
                
                if not target:
                    return jsonify({'error': 'Target is required'})
                
                result = self.port_scan(target, ports_str)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': f'Server error: {str(e)}'})

        @self.app.route('/report')
        def generate_report():
            try:
                if not self.analysis_results:
                    return jsonify({'success': False, 'message': 'No analysis data available'})
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_filename = f"security_report_{timestamp}.html"
                report_path = os.path.join('reports', report_filename)
                
                # Generate detailed HTML report
                html_content = self.generate_detailed_report()
                
                with open(report_path, 'w') as f:
                    f.write(html_content)
                
                return jsonify({'success': True, 'filename': report_filename})
                
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error generating report: {str(e)}'})

        @self.app.route('/download/<filename>')
        def download_report(filename):
            try:
                return send_file(os.path.join('reports', filename), as_attachment=True)
            except Exception as e:
                return f"Error downloading file: {str(e)}", 404

    def generate_detailed_report(self):
        """Generate detailed HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 40px; text-align: center; }}
        .content {{ padding: 40px; }}
        .section {{ margin: 30px 0; padding: 25px; background: #f8f9fa; border-radius: 10px; border-left: 4px solid #007bff; }}
        .section.warning {{ border-left-color: #ffc107; background: #fff3cd; }}
        .section.danger {{ border-left-color: #dc3545; background: #f8d7da; }}
        .section.success {{ border-left-color: #28a745; background: #d4edda; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; }}
        .badge-primary {{ background: #007bff; }}
        .badge-warning {{ background: #ffc107; color: #000; }}
        .badge-danger {{ background: #dc3545; }}
        .badge-success {{ background: #28a745; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 3px 10px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .footer {{ margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 10px; text-align: center; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Security Analysis Report</h1>
            <p>Comprehensive Log Analysis & Threat Assessment</p>
            <p><strong>Generated:</strong> {timestamp}</p>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len(self.log_data)}</div>
                    <div>Total Log Entries</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.analysis_results.get('ip_analysis', {}).get('total_unique_ips', 0)}</div>
                    <div>Unique IP Addresses</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.analysis_results.get('status_analysis', {}).get('total_errors', 0)}</div>
                    <div>HTTP Errors</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.analysis_results.get('suspicious_activity', {}).get('total_suspicious', 0)}</div>
                    <div>Security Threats</div>
                </div>
            </div>'''
        
        # IP Analysis Section
        if 'ip_analysis' in self.analysis_results:
            ip_data = self.analysis_results['ip_analysis']
            section_class = "warning" if ip_data.get('suspicious_ips') else "success"
            
            html += f'''
            <div class="section {section_class}">
                <h2>🌐 IP Address Analysis</h2>
                <p><strong>Total Unique IPs:</strong> {ip_data.get('total_unique_ips', 0)}</p>
                
                <h3>Top Requesting IPs</h3>
                <table>
                    <tr><th>IP Address</th><th>Request Count</th><th>Percentage</th></tr>'''
            
            total_requests = len(self.log_data)
            for ip, count in ip_data.get('top_ips', [])[:10]:
                percentage = (count / total_requests * 100) if total_requests > 0 else 0
                html += f'<tr><td>{ip}</td><td><span class="badge badge-primary">{count}</span></td><td>{percentage:.1f}%</td></tr>'
            
            html += '</table>'
            
            # Suspicious IPs
            if ip_data.get('suspicious_ips'):
                html += '<h3>🚨 Suspicious IP Addresses</h3><table>'
                html += '<tr><th>IP Address</th><th>Request Count</th><th>Reason</th><th>Risk Level</th></tr>'
                
                for sus_ip in ip_data['suspicious_ips'][:10]:
                    risk_level = "High" if sus_ip['count'] > 200 else "Medium"
                    badge_color = "badge-danger" if risk_level == "High" else "badge-warning"
                    html += f'<tr><td>{sus_ip["ip"]}</td><td><span class="badge {badge_color}">{sus_ip["count"]}</span></td><td>{sus_ip["reason"]}</td><td><span class="badge {badge_color}">{risk_level}</span></td></tr>'
                
                html += '</table>'
            else:
                html += '<div class="section success"><h3>✅ No suspicious IP activity detected</h3></div>'
            
            html += '</div>'
        
        # Status Code Analysis
        if 'status_analysis' in self.analysis_results:
            status_data = self.analysis_results['status_analysis']
            section_class = "danger" if status_data.get('error_rate', 0) > 10 else "success"
            
            html += f'''
            <div class="section {section_class}">
                <h2>📊 HTTP Status Code Analysis</h2>
                <p><strong>Error Rate:</strong> {status_data.get('error_rate', 0):.2f}%</p>
                <p><strong>Total Errors:</strong> {status_data.get('total_errors', 0)}</p>
                
                <table>
                    <tr><th>Status Code</th><th>Count</th><th>Category</th><th>Description</th></tr>'''
            
            status_descriptions = {
                200: "OK - Successful requests",
                301: "Moved Permanently",
                302: "Found - Temporary redirect", 
                400: "Bad Request - Client error",
                401: "Unauthorized - Authentication required",
                403: "Forbidden - Access denied",
                404: "Not Found - Resource missing",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable"
            }
            
            for code, count in status_data.get('status_distribution', {}).items():
                code_int = int(code)
                if code_int < 300:
                    category = "Success"
                    badge_class = "badge-success"
                elif code_int < 400:
                    category = "Redirect"
                    badge_class = "badge-primary"
                elif code_int < 500:
                    category = "Client Error"
                    badge_class = "badge-warning"
                else:
                    category = "Server Error"
                    badge_class = "badge-danger"
                
                description = status_descriptions.get(code_int, "Standard HTTP response")
                html += f'<tr><td>{code}</td><td><span class="badge {badge_class}">{count}</span></td><td>{category}</td><td>{description}</td></tr>'
            
            html += '</table></div>'
        
        # Security Threats
        if 'suspicious_activity' in self.analysis_results:
            sus_data = self.analysis_results['suspicious_activity']
            section_class = "danger" if sus_data.get('total_suspicious', 0) > 0 else "success"
            
            html += f'<div class="section {section_class}"><h2>⚠️ Security Threat Analysis</h2>'
            
            if sus_data.get('attack_types'):
                html += '<h3>Attack Types Detected</h3><table>'
                html += '<tr><th>Attack Type</th><th>Attempts</th><th>Severity</th><th>Description</th></tr>'
                
                attack_descriptions = {
                    'Directory Traversal': 'Attempts to access files outside web root',
                    'XSS Attempt': 'Cross-site scripting injection attempts', 
                    'SQL Injection': 'Database manipulation attempts',
                    'Command Injection': 'Operating system command execution attempts',
                    'WordPress Attack': 'WordPress-specific attack patterns',
                    'phpMyAdmin Attack': 'Database admin panel access attempts'
                }
                
                for attack_type, count in sus_data['attack_types'].items():
                    severity = "Critical" if count > 10 else "High" if count > 5 else "Medium"
                    badge_color = "badge-danger" if severity == "Critical" else "badge-warning"
                    description = attack_descriptions.get(attack_type, "Security threat detected")
                    
                    html += f'<tr><td>{attack_type}</td><td><span class="badge {badge_color}">{count}</span></td><td><span class="badge {badge_color}">{severity}</span></td><td>{description}</td></tr>'
                
                html += '</table>'
                
                # Recent attacks timeline
                if sus_data.get('recent_attacks'):
                    html += '<h3>Recent Attack Timeline</h3><table>'
                    html += '<tr><th>Timestamp</th><th>Attack Type</th><th>Source IP</th><th>Line Number</th></tr>'
                    
                    for attack in sus_data['recent_attacks'][-10:]:
                        html += f'<tr><td>{attack.get("timestamp", "Unknown")}</td><td><span class="badge badge-danger">{attack.get("type", "Unknown")}</span></td><td>{attack.get("ip", "Unknown")}</td><td>{attack.get("line", "N/A")}</td></tr>'
                    
                    html += '</table>'
            else:
                html += '<div class="section success"><h3>✅ No security threats detected</h3><p>Your logs show no signs of common attack patterns.</p></div>'
            
            html += '</div>'
        
        # Recommendations
        html += '''
        <div class="section">
            <h2>💡 Security Recommendations</h2>
            <ul>
                <li><strong>Monitor High-Traffic IPs:</strong> Investigate IPs with unusually high request volumes</li>
                <li><strong>Implement Rate Limiting:</strong> Prevent brute force attacks and API abuse</li>
                <li><strong>Update Security Rules:</strong> Block known attack patterns at firewall level</li>
                <li><strong>Regular Log Analysis:</strong> Schedule automated security scans</li>
                <li><strong>Error Monitoring:</strong> Set up alerts for high error rates</li>
                <li><strong>Access Control:</strong> Review and strengthen authentication mechanisms</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Report generated by Seralog</p>
            <p>For more information and advanced features, visit our documentation</p>
        </div>
        
        </div>
    </div>
</body>
</html>'''
        
        return html

    def run(self, host='127.0.0.1', port=5000, debug=True):
        """Run the web application"""
        print(f"🚀 Starting Log Analyzer Web App...")
        print(f"🌐 Access the application at: http://{host}:{port}")
        print(f"📝 Upload log files and analyze security threats")
        print(f"🛑 Press Ctrl+C to stop the server")
        
        try:
            self.app.run(host=host, port=port, debug=debug)
        except KeyboardInterrupt:
            print("\n👋 Log Analyzer stopped")


def main():
    """Main function to run the web app"""
    if not FLASK_AVAILABLE:
        print("❌ Flask is required for the web interface")
        print("📦 Install with: pip install flask")
        print("🔄 Or use the command-line version instead")
        return
    
    analyzer = LogAnalyzerWeb()
    analyzer.run()


if __name__ == "__main__":
    main()