#!/usr/bin/env python3
"""
Log Analyzer for Cybersecurity - Main Entry Point
A desktop tool for analyzing log files with focus on cybersecurity analysis.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui import LogAnalyzerGUI

def main():
    """Main function to launch the Log Analyzer GUI application."""
    try:
        app = LogAnalyzerGUI()
        app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error launching application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
