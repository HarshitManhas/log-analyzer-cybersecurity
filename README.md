# Log Analyzer for Cybersecurity

A powerful desktop tool built with Python and Tkinter for analyzing log files with a focus on cybersecurity analysis. This application helps developers, system administrators, and cybersecurity professionals quickly identify security threats, analyze traffic patterns, and monitor system performance through an intuitive graphical interface.

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green)

## Features

### 🔍 **Comprehensive Log Analysis**
- **IP Address Analysis**: Identify internal vs external IPs, detect suspicious activity patterns
- **URL/Endpoint Monitoring**: Track most accessed resources and API endpoints
- **HTTP Status Code Analysis**: Monitor success rates, error patterns, and response distributions
- **User Agent Detection**: Identify bots, crawlers, and potential automated attacks

### 🛡️ **Security-Focused Detection**
- **SQL Injection Detection**: Pattern matching for common SQL injection attempts
- **XSS Attack Identification**: Detection of cross-site scripting attempts
- **Brute Force Detection**: Identify suspicious login patterns and repeated failed attempts
- **Suspicious IP Flagging**: Automatic flagging of high-frequency or potentially malicious IPs
- **Bot Activity Analysis**: Distinguish between legitimate and malicious automated traffic

### 📊 **Interactive GUI Interface**
- **Tabbed Interface**: Organized views for different analysis aspects
- **Real-time Analysis**: Threaded processing to prevent GUI freezing
- **Export Capabilities**: Generate reports in text format or export raw data as JSON
- **Visual Data Presentation**: Organized tables and summaries for easy interpretation

### 🔧 **Technical Capabilities**
- **Multiple Log Formats**: Support for Apache, Nginx, and custom log formats
- **Regex-based Parsing**: Flexible pattern matching for various log structures
- **Timestamp Analysis**: Time-based event tracking and pattern identification
- **Error Categorization**: Automatic classification of different error types

## Installation

### Prerequisites
- Python 3.7 or higher
- Tkinter (usually included with Python)
- Standard Python libraries (re, os, datetime, collections, threading, json, ipaddress)

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd log-analyzer-cybersec
   ```

2. **Install dependencies** (optional, mostly uses stdlib):
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

### Alternative Installation
```bash
pip install -e .
log-analyzer
```

## Usage

### Getting Started

1. **Launch the Application**
   ```bash
   python main.py
   ```

2. **Select a Log File**
   - Click "Browse" to select your log file
   - Supported formats: `.log`, `.txt`, or any text-based log file

3. **Analyze the Logs**
   - Click "Analyze Log" to start the analysis
   - Wait for processing to complete

4. **Review Results**
   - Navigate through different tabs to view analysis results
   - Export reports or raw data as needed

### Understanding the Interface

#### **Summary Tab**
- Overview of file statistics
- Key metrics and counts
- Security alerts summary
- Error rate analysis

#### **IP Analysis Tab**
- Top IP addresses by request count
- Classification: Internal vs External IPs
- Suspicious activity flags
- Geographic and frequency analysis

#### **Security Analysis Tab**
- Security alert notifications
- Attack type detection counts
- Threat level indicators
- Detailed security metrics

#### **Traffic Analysis Tab**
- HTTP status code distribution
- Most requested URLs/endpoints
- Traffic pattern analysis
- Performance indicators

#### **Raw Data Tab**
- Complete JSON export of all analysis results
- Detailed technical data for further processing
- Machine-readable format for integration

## Cybersecurity Use Cases

### 🔒 **Security Monitoring**
- **Incident Response**: Quickly analyze logs during security incidents
- **Threat Hunting**: Proactive searching for indicators of compromise
- **Attack Pattern Recognition**: Identify recurring attack methodologies
- **Compliance Auditing**: Generate reports for security compliance requirements

### 📈 **Operational Intelligence**
- **Performance Monitoring**: Identify slow endpoints and error patterns
- **Capacity Planning**: Analyze traffic trends for infrastructure planning
- **User Behavior Analysis**: Understand normal vs anomalous user patterns
- **System Health Monitoring**: Track error rates and system stability

### 🕵️ **Forensic Analysis**
- **Post-Incident Analysis**: Detailed examination of security events
- **Timeline Reconstruction**: Chronological analysis of events
- **Evidence Collection**: Structured data export for legal proceedings
- **Pattern Correlation**: Connect related security events across time

## Sample Log Analysis

The application comes with sample log files in the `examples/` directory:

- **`apache_access.log`**: Sample Apache web server logs with various attack patterns
- **`security_events.log`**: Security-focused log entries with threat indicators

### Example Security Detections

```
⚠️ Potential SQL injection attempts detected: 3
⚠️ Potential XSS attempts detected: 2
⚠️ Suspicious IPs detected: 4
```

## Technical Details

### Supported Log Formats

#### **Apache Common Log Format**
```
192.168.1.100 - - [10/Jan/2024:13:55:36 -0700] "GET / HTTP/1.1" 200 2326
```

#### **Apache Combined Log Format**
```
192.168.1.100 - - [10/Jan/2024:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0..."
```

#### **Custom Security Logs**
```
2024-01-10 13:55:30 ERROR [SecurityModule] Suspicious login attempt detected
```

### Detection Patterns

The analyzer uses advanced regex patterns to identify:
- **IP Addresses**: IPv4 pattern matching with private/public classification
- **SQL Injection**: Common SQL keywords and injection patterns
- **XSS Attacks**: Script tags and JavaScript injection attempts
- **Login Attempts**: Authentication-related keywords and patterns
- **Error Keywords**: System errors, failures, and security alerts

### Performance Considerations

- **Threaded Processing**: Analysis runs in background threads to maintain GUI responsiveness
- **Memory Efficient**: Processes files line by line for large log files
- **Configurable Thresholds**: Adjustable sensitivity for threat detection
- **Scalable Architecture**: Modular design for easy extension

## Configuration

### Customizing Detection Patterns

Edit `src/log_analyzer.py` to modify regex patterns:

```python
self.patterns = {
    'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'sql_injection': r'(?i)(union|select|insert|update|delete|drop)',
    # Add custom patterns here
}
```

### Adjusting Sensitivity Thresholds

Modify suspicious activity thresholds:

```python
# In _extract_ip_addresses method
if ip_counter[ip] > 100:  # Adjust threshold as needed
    suspicious_ips.append(ip)
```

## Development

### Project Structure

```
log-analyzer-cybersec/
├── main.py                 # Application entry point
├── src/
│   ├── log_analyzer.py     # Core analysis engine
│   └── gui.py              # Tkinter GUI interface
├── examples/               # Sample log files
│   ├── apache_access.log
│   └── security_events.log
├── tests/                  # Unit tests
├── docs/                   # Documentation
├── requirements.txt        # Dependencies
├── setup.py               # Package configuration
└── README.md              # This file
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

### Adding New Features

#### **Custom Log Parsers**
Extend the `LogAnalyzer` class to support additional log formats:

```python
def _parse_custom_format(self, content):
    # Implement custom parsing logic
    pass
```

#### **Additional Security Patterns**
Add new threat detection patterns:

```python
'custom_threat': r'your_regex_pattern_here'
```

#### **GUI Enhancements**
Extend the GUI with new tabs or visualizations:

```python
def create_custom_tab(self):
    # Implement new GUI tab
    pass
```

## Troubleshooting

### Common Issues

**GUI doesn't start**
- Ensure Tkinter is installed: `python -m tkinter`
- Check Python version compatibility (3.7+)

**Large files cause freezing**
- Analysis runs in background threads, but very large files may take time
- Consider splitting large files or increasing system memory

**Patterns not matching**
- Verify log format compatibility
- Check regex patterns in `log_analyzer.py`
- Test with provided sample files first

### Performance Optimization

- **File Size**: Optimal performance with files under 100MB
- **Memory Usage**: Monitor system resources for very large files  
- **Threading**: GUI remains responsive during analysis

## Future Enhancements

### Planned Features
- [ ] **Real-time Log Monitoring**: Live log file watching and analysis
- [ ] **Advanced Visualizations**: Charts and graphs using matplotlib
- [ ] **Machine Learning Integration**: Anomaly detection using scikit-learn
- [ ] **Database Integration**: Store and query analysis results
- [ ] **Network Analysis**: Enhanced IP geolocation and threat intelligence
- [ ] **Custom Rules Engine**: User-defined detection rules
- [ ] **Report Templates**: Customizable report formats
- [ ] **API Integration**: Connect with SIEM and security tools

### Enhancement Ideas
- **Multi-file Analysis**: Process multiple log files simultaneously
- **Scheduled Analysis**: Automated periodic log processing
- **Alert System**: Real-time notifications for critical threats
- **Export Formats**: PDF reports, CSV data, XML output

## License

This project is for educational purpose.

## Acknowledgments

- Built with Python's robust standard library
- Tkinter GUI framework for cross-platform compatibility
- Regex patterns inspired by common security threats
- Community feedback and contributions

## Contact

For questions, suggestions, or support:

- Create an issue on GitHub
- Email: [harshit.manhas.9@gmail.com]

---

**⚠️ Security Notice**: This tool is designed for legitimate security analysis and system administration purposes. Always ensure you have proper authorization before analyzing log files that don't belong to you.
