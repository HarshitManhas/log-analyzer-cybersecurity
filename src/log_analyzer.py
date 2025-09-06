"""
Log Analyzer Core Engine
Handles parsing and analysis of log files with cybersecurity focus.
"""

import re
import os
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any
import ipaddress

class LogAnalyzer:
    """Core log analysis engine for cybersecurity purposes."""
    
    def __init__(self):
        """Initialize the LogAnalyzer with regex patterns."""
        self.patterns = {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'url': r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)',
            'status_code': r'\s([1-5][0-9]{2})\s',
            'timestamp_apache': r'\[([^\]]+)\]',
            'timestamp_nginx': r'^(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})',
            'user_agent': r'"([^"]*)"(?:\s|$)',
            'error_keywords': r'(?i)(error|fail|exception|critical|alert|warning|denied|blocked|attack|intrusion|malware|virus|suspicious)',
            'http_methods': r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\b',
            'sql_injection': r'(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)',
            'xss_patterns': r'(?i)(&lt;script|&lt;img|javascript:|vbscript:|onload=|onerror=)',
            'login_attempts': r'(?i)(login|auth|signin|password|failed|success|attempt)',
        }
        
        self.compiled_patterns = {name: re.compile(pattern) 
                                 for name, pattern in self.patterns.items()}
        
        self.analysis_results = {}
        self.security_alerts = []
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a single log file and extract key information.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            results = {
                'file_info': self._get_file_info(file_path),
                'ip_addresses': self._extract_ip_addresses(content),
                'urls': self._extract_urls(content),
                'status_codes': self._extract_status_codes(content),
                'timestamps': self._extract_timestamps(content),
                'user_agents': self._extract_user_agents(content),
                'security_analysis': self._perform_security_analysis(content),
                'error_analysis': self._analyze_errors(content),
                'traffic_analysis': self._analyze_traffic_patterns(content)
            }
            
            self.analysis_results = results
            return results
            
        except Exception as e:
            raise Exception(f"Error analyzing file {file_path}: {str(e)}")
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information."""
        stat = os.stat(file_path)
        return {
            'name': os.path.basename(file_path),
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'path': file_path
        }
    
    def _extract_ip_addresses(self, content: str) -> Dict[str, Any]:
        """Extract and analyze IP addresses."""
        ips = self.compiled_patterns['ip_address'].findall(content)
        ip_counter = Counter(ips)
        
        # Classify IPs
        internal_ips = []
        external_ips = []
        suspicious_ips = []
        
        for ip in set(ips):
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    internal_ips.append(ip)
                else:
                    external_ips.append(ip)
                    
                # Check for suspicious patterns (high frequency)
                if ip_counter[ip] > 100:  # Configurable threshold
                    suspicious_ips.append(ip)
                    
            except ipaddress.AddressValueError:
                continue
        
        return {
            'total_count': len(ips),
            'unique_count': len(set(ips)),
            'top_ips': ip_counter.most_common(10),
            'internal_ips': internal_ips,
            'external_ips': external_ips,
            'suspicious_ips': suspicious_ips
        }
    
    def _extract_urls(self, content: str) -> Dict[str, Any]:
        """Extract and analyze URLs/endpoints."""
        urls = self.compiled_patterns['url'].findall(content)
        url_counter = Counter(urls)
        
        return {
            'total_requests': len(urls),
            'unique_endpoints': len(set(urls)),
            'top_endpoints': url_counter.most_common(10),
            'all_urls': list(set(urls))
        }
    
    def _extract_status_codes(self, content: str) -> Dict[str, Any]:
        """Extract and analyze HTTP status codes."""
        status_codes = self.compiled_patterns['status_code'].findall(content)
        status_counter = Counter(status_codes)
        
        # Categorize status codes
        success_codes = [code for code in status_codes if code.startswith('2')]
        client_errors = [code for code in status_codes if code.startswith('4')]
        server_errors = [code for code in status_codes if code.startswith('5')]
        
        return {
            'total_responses': len(status_codes),
            'status_distribution': dict(status_counter),
            'success_rate': len(success_codes) / len(status_codes) * 100 if status_codes else 0,
            'client_error_rate': len(client_errors) / len(status_codes) * 100 if status_codes else 0,
            'server_error_rate': len(server_errors) / len(status_codes) * 100 if status_codes else 0,
            'top_status_codes': status_counter.most_common(10)
        }
    
    def _extract_timestamps(self, content: str) -> Dict[str, Any]:
        """Extract and analyze timestamps."""
        apache_timestamps = self.compiled_patterns['timestamp_apache'].findall(content)
        nginx_timestamps = self.compiled_patterns['timestamp_nginx'].findall(content)
        
        all_timestamps = apache_timestamps + nginx_timestamps
        
        return {
            'total_entries': len(all_timestamps),
            'format_detected': 'apache' if apache_timestamps else 'nginx' if nginx_timestamps else 'unknown',
            'first_entry': all_timestamps[0] if all_timestamps else None,
            'last_entry': all_timestamps[-1] if all_timestamps else None
        }
    
    def _extract_user_agents(self, content: str) -> Dict[str, Any]:
        """Extract and analyze user agents."""
        user_agents = self.compiled_patterns['user_agent'].findall(content)
        ua_counter = Counter(user_agents)
        
        # Identify potential bots/crawlers
        bot_patterns = ['bot', 'crawler', 'spider', 'scraper']
        bots = [ua for ua in user_agents if any(pattern.lower() in ua.lower() for pattern in bot_patterns)]
        
        return {
            'total_user_agents': len(user_agents),
            'unique_user_agents': len(set(user_agents)),
            'top_user_agents': ua_counter.most_common(5),
            'potential_bots': list(set(bots))
        }
    
    def _perform_security_analysis(self, content: str) -> Dict[str, Any]:
        """Perform security-focused analysis."""
        security_issues = []
        
        # Check for SQL injection attempts
        sql_matches = self.compiled_patterns['sql_injection'].findall(content)
        if sql_matches:
            security_issues.append(f"Potential SQL injection attempts detected: {len(sql_matches)}")
        
        # Check for XSS attempts
        xss_matches = self.compiled_patterns['xss_patterns'].findall(content)
        if xss_matches:
            security_issues.append(f"Potential XSS attempts detected: {len(xss_matches)}")
        
        # Check for login attempts
        login_matches = self.compiled_patterns['login_attempts'].findall(content)
        
        return {
            'sql_injection_attempts': len(sql_matches),
            'xss_attempts': len(xss_matches),
            'login_related_entries': len(login_matches),
            'security_alerts': security_issues
        }
    
    def _analyze_errors(self, content: str) -> Dict[str, Any]:
        """Analyze error patterns in logs."""
        error_matches = self.compiled_patterns['error_keywords'].findall(content)
        error_counter = Counter([match.lower() for match in error_matches])
        
        return {
            'total_errors': len(error_matches),
            'error_types': dict(error_counter),
            'top_errors': error_counter.most_common(5)
        }
    
    def _analyze_traffic_patterns(self, content: str) -> Dict[str, Any]:
        """Analyze traffic patterns."""
        methods = self.compiled_patterns['http_methods'].findall(content)
        method_counter = Counter(methods)
        
        return {
            'total_requests': len(methods),
            'method_distribution': dict(method_counter),
            'top_methods': method_counter.most_common(5)
        }
    
    def generate_summary_report(self) -> str:
        """Generate a text summary report of the analysis."""
        if not self.analysis_results:
            return "No analysis results available."
        
        report_lines = []
        report_lines.append("=== LOG ANALYSIS SUMMARY ===")
        report_lines.append("")
        
        # File info
        file_info = self.analysis_results.get('file_info', {})
        report_lines.append(f"File: {file_info.get('name', 'N/A')}")
        report_lines.append(f"Size: {file_info.get('size', 0)} bytes")
        report_lines.append("")
        
        # IP Analysis
        ip_data = self.analysis_results.get('ip_addresses', {})
        report_lines.append(f"IP Addresses: {ip_data.get('unique_count', 0)} unique ({ip_data.get('total_count', 0)} total)")
        if ip_data.get('suspicious_ips'):
            report_lines.append(f"Suspicious IPs: {len(ip_data['suspicious_ips'])}")
        
        # Security Analysis
        security_data = self.analysis_results.get('security_analysis', {})
        if security_data.get('security_alerts'):
            report_lines.append("")
            report_lines.append("SECURITY ALERTS:")
            for alert in security_data['security_alerts']:
                report_lines.append(f"  - {alert}")
        
        # Error Analysis
        error_data = self.analysis_results.get('error_analysis', {})
        report_lines.append("")
        report_lines.append(f"Errors detected: {error_data.get('total_errors', 0)}")
        
        # Status Codes
        status_data = self.analysis_results.get('status_codes', {})
        report_lines.append(f"Success rate: {status_data.get('success_rate', 0):.1f}%")
        
        return "\n".join(report_lines)
