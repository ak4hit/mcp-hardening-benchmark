from setuptools import setup, find_packages

setup(
    name="mcp-hardening-benchmark",
    version="1.0.0",
    description="CIS-Style Security Audit Tool for MCP Server Deployments",
    author="ak4hit",
    url="https://github.com/ak4hit/mcp-hardening-benchmark",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click",
        "rich",
        "requests",
        "jinja2",
        "packaging",
    ],
    entry_points={
        "console_scripts": [
            "mcp-audit=mcp_benchmark.cli.main:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
