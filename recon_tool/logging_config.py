# recon_tool/recon_tool/logging_config.py

import logging
import os
import time  # Added import to fix NameError

def setup_logging(log_dir: str, verbose: bool = False):
    """
    Setup logging configuration.

    Args:
        log_dir (str): Directory to store log files.
        verbose (bool): If True, set log level to DEBUG.
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, f'recon_log_{int(time.time())}.txt')

    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Logging to: {log_file}")
