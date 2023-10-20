import re
from ..FileHandler.read_file import Pattern

class DataValidator:
    """
    A class for validating different types of data.

    Attributes:
        pattern_IP (re.Pattern): A regular expression pattern for matching IP addresses.
        pattern_URL (re.Pattern): A regular expression pattern for matching URLs.
        pattern_Hash (re.Pattern): A regular expression pattern for matching hashes.
        pattern_Domain (re.Pattern): A regular expression pattern for matching domains.

    Methods:
        validate_ip(ip): Validate an IP address and determine its type.
        validate_domain(domain): Validate a domain and determine its type.
        validate_hash(h): Validate a hash value and determine its type.
        validate_url(u): Validate a URL and determine its type.

    """

    def __init__(self):
        self.pattern_IP = Pattern.pattern_IP
        self.pattern_URL = Pattern.pattern_URL
        self.pattern_Hash = Pattern.pattern_Hash
        self.pattern_Domain = Pattern.pattern_Domain

    def validate_ip(self, ip):
        """
        Validate an IP address and determine its type.

        Parameters:
        ip (str): The IP address to validate.

        Returns:
        str: The type of the IP address (one of "Private", "Localhost", "Everybody", "Public", or None).
        """
        ip_type = None  # Initialize the type to None

        # Check if the IP address is in the correct format
        if self.pattern_IP.match(ip):
            # Use regular expressions to match private, localhost, and "everybody" IP addresses
            ip_patterns = {
                "Private": r"^(0?10\.|172\.(0?1[6-9]|0?2[0-9]|0?3[0-1])\.|192\.168\.|127\.)\d{1,3}\.\d{1,3}$",
                "Localhost": r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                "Everybody": r"^0\.0\.0\.0$",
                "IP": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            }

            for ip_type, pattern in ip_patterns.items():
                if re.fullmatch(pattern, ip):
                    # Validate that each octet is a number between 0 and 255, inclusive
                    octets = ip.split(".")
                    if all(0 <= int(octet) <= 255 for octet in octets):
                        return ip_type

    def validate_domain(self, domain):
        """
        Validate a domain and determine its type.

        Parameters:
        domain (str): The domain to validate.

        Returns:
        str: The type of the domain (one of "Valid", "Invalid", or None).
        """
        domain_type = None  # Initialize the type to None
        pattern = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
        )

        # Check if the domain is in the correct format
        if pattern.match(domain):
            domain_type = "DOMAIN"  # Set the type to "DOMAIN

        return domain_type  # Return the type

    def validate_hash(self, h):
        """
        Validate a hash value and determine its type.

        Parameters:
        h (str): The hash value to validate.

        Returns:
        str: The type of the hash (one of "SHA-256" or None).
        """
        hash_type = None  # Initialize the type to None

        # Check if the hash is in the correct format
        if re.match(r'[a-fA-F0-9]{64}', h):
            if len(h) == 64:  # If the hash is 64 characters long
                hash_type = "HASH"  # Set the type to "SHA-256"

        return hash_type  # Return the type

    def validate_url(self, u):
        """
        Validate a URL and determine its type.

        Parameters:
        u (str): The URL to validate.

        Returns:
        str: The type of the URL (one of "Valid" or None).
        """
        url_type = None  # Initialize the type to None

        # Check if the URL is in the correct format
        if self.pattern_URL.match(u):
            url_type = "URL"  # Set the type to "Valid"

        return url_type  # Return the type