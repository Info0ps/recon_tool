# recon_tool/recon_tool/config.py

import configparser
import os
import logging

class ReconConfig:
    def __init__(self, config_file: str):
        self.config = configparser.ConfigParser()
        if not os.path.isfile(config_file):
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        self.config.read(config_file)

    def get(self, section: str, option: str, fallback=None):
        return self.config.get(section, option, fallback=fallback)

    def getint(self, section: str, option: str, fallback=0):
        """
        Override getint to ensure it handles sanitized integer values.
        """
        value_str = self.config.get(section, option, fallback=str(fallback))
        try:
            # Split the string on whitespace and take the first part
            sanitized_str = value_str.split()[0]
            return int(sanitized_str)
        except (ValueError, IndexError):
            logging.error(f"Invalid value for [{section}] {option}: '{value_str}'. Using fallback: {fallback}")
            return fallback

    def getboolean(self, section: str, option: str, fallback=False):
        return self.config.getboolean(section, option, fallback=fallback)
