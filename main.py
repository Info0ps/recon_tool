# recon_tool/main.py

#!/usr/bin/env python3

"""
DISCLAIMER: This script is intended for educational purposes and authorized penetration testing only.
Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical.
"""

import os
import sys
import argparse
import shutil
import subprocess
import importlib.util
import logging
from urllib.parse import urlparse
from recon_tool.config import ReconConfig
from recon_tool.logging_config import setup_logging
from recon_tool.scanners import ReconRunner
from recon_tool.ml_model import MLModel
from recon_tool.utils import is_valid_url, is_ip_address
import asyncio

# Add system site-packages to sys.path to recognize packages installed via apt
system_site_packages = '/usr/lib/python3/dist-packages'
if system_site_packages not in sys.path:
    sys.path.append(system_site_packages)

# Constants for default settings
DEFAULT_CONFIG_FILE = 'config/config.ini'

def check_dependencies():
    """
    Check if required Python packages and external tools are installed.
    If not, prompt the user to install them manually.
    """
    import importlib

    # Mapping of pip package names to Python module names
    required_packages = {
        'aiohttp': 'aiohttp',
        'beautifulsoup4': 'bs4',
        'joblib': 'joblib',
        'scikit-learn': 'sklearn',
        'numpy': 'numpy',
        'tqdm': 'tqdm',
        'configparser': 'configparser',
        'aiofiles': 'aiofiles',
        'jinja2': 'jinja2',
        'pandas': 'pandas'
    }

    missing_packages = []
    for pkg_name, module_name in required_packages.items():
        if importlib.util.find_spec(module_name) is None:
            missing_packages.append(pkg_name)

    if missing_packages:
        print(f"The following Python packages are missing: {', '.join(missing_packages)}")
        print("Please install them manually using the following commands:")
        print("\n1. Install packages available via apt:")
        apt_packages = []
        pip_packages = []
        for pkg in missing_packages:
            if pkg == 'beautifulsoup4':
                apt_packages.append('python3-bs4')
            elif pkg == 'scikit-learn':
                apt_packages.append('python3-sklearn')
            else:
                pip_packages.append(pkg)
        
        if apt_packages:
            print(f"   sudo apt install {' '.join(apt_packages)}")
        if pip_packages:
            print(f"\n2. Install remaining packages using pip:")
            print(f"   python3 -m pip install --user {' '.join(pip_packages)}")
        
        sys.exit(1)

    # Required external tools
    required_tools = ['nmap', 'ffuf', 'wafw00f', 'whatweb']
    missing_tools = []
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing_tools.append(tool)

    if missing_tools:
        print(f"The following external tools are missing: {', '.join(missing_tools)}")
        print("Please install them before running the script.")
        sys.exit(1)

def handle_exit(signum, frame):
    """
    Handle exit signals for graceful shutdown.

    Args:
        signum: Signal number.
        frame: Current stack frame.
    """
    logging.info("Process interrupted. Exiting gracefully...")
    sys.exit(0)

def setup_signal_handlers():
    """
    Setup signal handlers for graceful shutdown.
    """
    import signal
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

def main():
    """
    Main function to parse arguments and run recon.
    """
    parser = argparse.ArgumentParser(description='Reconnaissance Automation Tool with Advanced Features')
    parser.add_argument('--target', required=True, help='Target domain, IP address, or URL')
    parser.add_argument('--config', default=DEFAULT_CONFIG_FILE, help='Path to configuration file')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    target_input = args.target
    parsed = urlparse(target_input)

    if parsed.scheme and parsed.netloc:
        target = parsed.netloc
    else:
        target = target_input if is_ip_address(target_input) else target_input

    if not is_valid_url(f"http://{target}"):
        print("Invalid target provided. Please provide a valid domain, IP address, or URL.")
        sys.exit(1)

    # Run dependency check
    check_dependencies()

    setup_signal_handlers()
    config = ReconConfig(args.config)
    setup_logging(config.get('DEFAULT', 'LogDir', fallback='logs'), args.verbose)

    ml_model = MLModel(config.get('DEFAULT', 'MLModelPath'))

    runner = ReconRunner(target, config, ml_model, verbose=args.verbose)
    asyncio.run(runner.run())

if __name__ == "__main__":
    main()
