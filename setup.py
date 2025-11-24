#!/usr/bin/env python3
"""
Setup script for netmon package.

This file exists for backwards compatibility with older build tools.
The primary configuration is in pyproject.toml.
"""

from setuptools import setup

# Read long description from README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="netmon",
    version="1.0.0",
    author="Harry Coin",
    author_email="hcoin@quietfountain.com",
    description="Comprehensive Linux network snapshot toolkit/python library using RTNetlink and Generic Netlink",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hcoin/netmon",
    project_urls={
        "Bug Tracker": "https://github.com/hcoin/netmon/issues",
        "Documentation": "https://github.com/hcoin/netmon#readme",
        "Source Code": "https://github.com/hcoin/netmon",
    },
    packages=["netmon"],
    package_data={
        "netmon": ["*.html"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cffi>=1.0.0",
        "setuptools>=61.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netmon-device=netmon.device_info:main",
            "netmon-route=netmon.route_info:main",
            "netmon-neighbor=netmon.neighbor_info:main",
            "netmon-mdb=netmon.mdb_info:main",
            "netmon-rule=netmon.rule_info:main",
        ],
    },
)
