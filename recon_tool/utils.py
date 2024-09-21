# recon_tool/recon_tool/utils.py

import random
import string
from urllib.parse import urlparse

def is_valid_url(url: str) -> bool:
    """
    Validate the given URL.

    Args:
        url (str): URL to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_ip_address(address: str) -> bool:
    """
    Check if the given string is an IP address.

    Args:
        address (str): String to check.

    Returns:
        bool: True if IP address, False otherwise.
    """
    try:
        import ipaddress
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def randomize_case(s: str) -> str:
    """
    Randomize the case of a given string.

    Args:
        s (str): String to randomize.

    Returns:
        str: Randomized case string.
    """
    return ''.join(random.choice([char.upper(), char.lower()]) for char in s)
