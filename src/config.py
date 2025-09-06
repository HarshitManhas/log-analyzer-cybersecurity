"""
Configuration settings for Log Analyzer
"""

# Application Settings
APP_NAME = "Log Analyzer for Cybersecurity"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Your Name"

# GUI Settings
DEFAULT_WINDOW_WIDTH = 1200
DEFAULT_WINDOW_HEIGHT = 800
DEFAULT_WINDOW_TITLE = f"{APP_NAME} v{APP_VERSION}"

# Analysis Settings
SUSPICIOUS_IP_THRESHOLD = 100  # Number of requests to consider IP suspicious
MAX_FILE_SIZE_MB = 500  # Maximum file size to process (in MB)
ANALYSIS_TIMEOUT = 300  # Analysis timeout in seconds

# Log Format Settings
SUPPORTED_EXTENSIONS = ['.log', '.txt']
DEFAULT_ENCODING = 'utf-8'

# Export Settings
DEFAULT_REPORT_FILENAME = "log_analysis_report.txt"
DEFAULT_JSON_FILENAME = "log_analysis_data.json"

# Security Patterns Configuration
SECURITY_KEYWORDS = [
    'error', 'fail', 'exception', 'critical', 'alert', 'warning',
    'denied', 'blocked', 'attack', 'intrusion', 'malware', 'virus',
    'suspicious', 'breach', 'compromise', 'unauthorized'
]

SQL_INJECTION_KEYWORDS = [
    'union', 'select', 'insert', 'update', 'delete', 'drop',
    'create', 'alter', 'exec', 'script', 'declare', 'cast'
]

XSS_PATTERNS = [
    '&lt;script', '&lt;img', 'javascript:', 'vbscript:',
    'onload=', 'onerror=', 'onclick=', 'onmouseover='
]

# Network Settings
PRIVATE_IP_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12', 
    '192.168.0.0/16',
    '127.0.0.0/8'
]

# GUI Theme Settings
GUI_THEME = {
    'bg_color': '#f0f0f0',
    'text_color': '#333333',
    'accent_color': '#0078d4',
    'error_color': '#d13438',
    'warning_color': '#ff8c00',
    'success_color': '#107c10'
}

# File Paths
LOG_FILE_EXTENSIONS = ['*.log', '*.txt']
EXPORT_FILE_TYPES = [
    ('Text files', '*.txt'),
    ('JSON files', '*.json'),
    ('All files', '*.*')
]

# Performance Settings
CHUNK_SIZE = 8192  # File read chunk size in bytes
MAX_DISPLAY_ITEMS = 1000  # Maximum items to display in GUI tables
THREAD_TIMEOUT = 30  # Thread timeout in seconds
