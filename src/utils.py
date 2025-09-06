"""
Utility functions for Log Analyzer
"""

import os
import re
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional
import config

def format_file_size(size_bytes: int) -> str:
    """Convert file size in bytes to human-readable format."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    size_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and size_index < len(size_names) - 1:
        size /= 1024
        size_index += 1
    
    return f"{size:.1f} {size_names[size_index]}"

def validate_file_path(file_path: str) -> Dict[str, Any]:
    """
    Validate if the file path is accessible and suitable for analysis.
    
    Returns:
        Dictionary with validation results
    """
    result = {
        'valid': False,
        'error': None,
        'warnings': [],
        'info': {}
    }
    
    try:
        if not os.path.exists(file_path):
            result['error'] = "File does not exist"
            return result
        
        if not os.path.isfile(file_path):
            result['error'] = "Path is not a file"
            return result
        
        # Check file size
        file_size = os.path.getsize(file_path)
        max_size = config.MAX_FILE_SIZE_MB * 1024 * 1024
        
        result['info']['size'] = file_size
        result['info']['size_formatted'] = format_file_size(file_size)
        
        if file_size > max_size:
            result['warnings'].append(f"File size ({format_file_size(file_size)}) exceeds recommended maximum ({config.MAX_FILE_SIZE_MB} MB)")
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() not in config.SUPPORTED_EXTENSIONS:
            result['warnings'].append(f"File extension {ext} is not typically supported")
        
        # Check file permissions
        if not os.access(file_path, os.R_OK):
            result['error'] = "File is not readable"
            return result
        
        result['valid'] = True
        
    except Exception as e:
        result['error'] = f"Error validating file: {str(e)}"
    
    return result

def is_private_ip(ip_address: str) -> bool:
    """Check if an IP address is private."""
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except (ipaddress.AddressValueError, ValueError):
        return False

def classify_ip(ip_address: str) -> str:
    """Classify IP address type."""
    try:
        ip = ipaddress.ip_address(ip_address)
        
        if ip.is_private:
            return "Internal"
        elif ip.is_loopback:
            return "Loopback"
        elif ip.is_multicast:
            return "Multicast"
        elif ip.is_reserved:
            return "Reserved"
        else:
            return "External"
            
    except (ipaddress.AddressValueError, ValueError):
        return "Invalid"

def extract_timestamp_info(timestamp_str: str) -> Optional[Dict[str, Any]]:
    """Extract and parse timestamp information."""
    if not timestamp_str:
        return None
    
    # Common timestamp patterns
    patterns = [
        # Apache format: [10/Jan/2024:13:55:36 -0700]
        (r'\[([^\]]+)\]', '%d/%b/%Y:%H:%M:%S %z'),
        # ISO format: 2024-01-10 13:55:36
        (r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
        # Syslog format: Jan 10 13:55:36
        (r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
    ]
    
    for pattern, format_str in patterns:
        match = re.search(pattern, timestamp_str)
        if match:
            try:
                timestamp = match.group(1)
                if '%z' in format_str:
                    # Handle timezone offset
                    dt = datetime.strptime(timestamp, format_str)
                else:
                    dt = datetime.strptime(timestamp, format_str)
                    # Assume current year if not specified
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                
                return {
                    'datetime': dt,
                    'formatted': dt.strftime('%Y-%m-%d %H:%M:%S'),
                    'timestamp': dt.timestamp()
                }
            except ValueError:
                continue
    
    return None

def calculate_percentage(part: int, total: int) -> float:
    """Calculate percentage with zero division protection."""
    if total == 0:
        return 0.0
    return (part / total) * 100

def truncate_text(text: str, max_length: int = 50) -> str:
    """Truncate text to specified length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing/replacing invalid characters."""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Ensure filename is not empty
    if not filename:
        filename = "untitled"
    
    return filename

def create_summary_stats(data_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Create summary statistics from analysis data."""
    stats = {}
    
    # Basic counts
    if 'ip_addresses' in data_dict:
        ip_data = data_dict['ip_addresses']
        stats['total_ips'] = ip_data.get('total_count', 0)
        stats['unique_ips'] = ip_data.get('unique_count', 0)
        stats['suspicious_ips'] = len(ip_data.get('suspicious_ips', []))
    
    if 'status_codes' in data_dict:
        status_data = data_dict['status_codes']
        stats['total_responses'] = status_data.get('total_responses', 0)
        stats['success_rate'] = status_data.get('success_rate', 0)
        stats['error_rate'] = status_data.get('client_error_rate', 0) + status_data.get('server_error_rate', 0)
    
    if 'security_analysis' in data_dict:
        security_data = data_dict['security_analysis']
        stats['security_alerts'] = len(security_data.get('security_alerts', []))
        stats['sql_injection_attempts'] = security_data.get('sql_injection_attempts', 0)
        stats['xss_attempts'] = security_data.get('xss_attempts', 0)
    
    return stats

def validate_regex_pattern(pattern: str) -> Dict[str, Any]:
    """Validate a regex pattern."""
    result = {'valid': False, 'error': None}
    
    try:
        re.compile(pattern)
        result['valid'] = True
    except re.error as e:
        result['error'] = f"Invalid regex pattern: {str(e)}"
    
    return result

def export_data_to_csv(data: List[Dict[str, Any]], filename: str) -> bool:
    """Export data to CSV format (basic implementation)."""
    try:
        import csv
        
        if not data:
            return False
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            if isinstance(data[0], dict):
                fieldnames = data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            else:
                writer = csv.writer(csvfile)
                for row in data:
                    writer.writerow(row)
        
        return True
    except Exception:
        return False

def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """Get comprehensive file metadata."""
    try:
        stat = os.stat(file_path)
        return {
            'name': os.path.basename(file_path),
            'path': file_path,
            'size': stat.st_size,
            'size_formatted': format_file_size(stat.st_size),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'extension': os.path.splitext(file_path)[1],
            'directory': os.path.dirname(file_path)
        }
    except Exception:
        return {'error': 'Could not retrieve file metadata'}

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable format."""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

class LogPatternMatcher:
    """Utility class for advanced log pattern matching."""
    
    def __init__(self):
        self.compiled_patterns = {}
    
    def add_pattern(self, name: str, pattern: str):
        """Add a new pattern to the matcher."""
        try:
            self.compiled_patterns[name] = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid pattern '{name}': {str(e)}")
    
    def match_pattern(self, name: str, text: str) -> List[str]:
        """Match a pattern against text."""
        if name not in self.compiled_patterns:
            return []
        
        return self.compiled_patterns[name].findall(text)
    
    def match_all_patterns(self, text: str) -> Dict[str, List[str]]:
        """Match all patterns against text."""
        results = {}
        for name, pattern in self.compiled_patterns.items():
            results[name] = pattern.findall(text)
        return results
