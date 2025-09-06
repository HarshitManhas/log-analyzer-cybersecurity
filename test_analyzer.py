#!/usr/bin/env python3
"""
Test script for Log Analyzer functionality
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from log_analyzer import LogAnalyzer

def test_analyzer():
    """Test the log analyzer with sample files."""
    print("=== Log Analyzer Test ===")
    
    analyzer = LogAnalyzer()
    
    # Test Apache log
    print("\n1. Testing Apache access log analysis...")
    try:
        results = analyzer.analyze_file('examples/apache_access.log')
        print(f"✓ Analysis completed successfully")
        print(f"  - Unique IPs: {results['ip_addresses']['unique_count']}")
        print(f"  - Total requests: {results['urls']['total_requests']}")
        print(f"  - Security alerts: {len(results['security_analysis']['security_alerts'])}")
        print(f"  - Status codes analyzed: {results['status_codes']['total_responses']}")
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    # Test security events log
    print("\n2. Testing security events log analysis...")
    try:
        results = analyzer.analyze_file('examples/security_events.log')
        print(f"✓ Analysis completed successfully")
        print(f"  - Unique IPs: {results['ip_addresses']['unique_count']}")
        print(f"  - Error entries: {results['error_analysis']['total_errors']}")
        print(f"  - Security alerts: {len(results['security_analysis']['security_alerts'])}")
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    # Test summary report generation
    print("\n3. Testing report generation...")
    try:
        report = analyzer.generate_summary_report()
        print(f"✓ Report generated ({len(report)} characters)")
    except Exception as e:
        print(f"✗ Error generating report: {e}")
        return False
    
    print("\n=== All Tests Passed! ===")
    print("\nTo run the GUI application:")
    print("  python3 main.py")
    
    return True

if __name__ == "__main__":
    success = test_analyzer()
    sys.exit(0 if success else 1)
