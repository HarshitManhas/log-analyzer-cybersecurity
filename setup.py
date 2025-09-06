"""
Setup script for Log Analyzer for Cybersecurity
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    return "Log Analyzer for Cybersecurity - A desktop tool for analyzing log files with focus on cybersecurity analysis."

setup(
    name="log-analyzer-cybersec",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A desktop tool for analyzing log files with focus on cybersecurity analysis",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/log-analyzer-cybersec",
    packages=find_packages(),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Logging",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.7",
    install_requires=[
        # Minimal dependencies as most functionality uses stdlib
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.10.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
        ],
        "viz": [
            "matplotlib>=3.5.0",
            "seaborn>=0.11.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "log-analyzer=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
