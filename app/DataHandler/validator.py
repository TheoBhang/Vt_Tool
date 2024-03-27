import re
import ipaddress
from app.FileHandler.read_file import Pattern

class DataValidator:
    """
    A class for validating different types of data.

    Attributes:
        pattern_ip (re.Pattern): A regular expression pattern for matching IP addresses.
        pattern_url (re.Pattern): A regular expression pattern for matching URLs.
        pattern_hash (re.Pattern): A regular expression pattern for matching hashes.
        pattern_domain (re.Pattern): A regular expression pattern for matching domains.

    Methods:
        validate_ip(ip): Validate an IP address and determine its type.
        validate_domain(domain): Validate a domain and determine its type.
        validate_hash(h): Validate a hash value and determine its type.
        validate_url(u): Validate a URL and determine its type.

    """

    def __init__(self):
        self.pattern_ip = Pattern.pattern_ip
        self.pattern_url = Pattern.pattern_url
        self.pattern_hash = Pattern.pattern_hash
        self.pattern_domain = Pattern.pattern_domain
        self.hash_regex = r'(?i)^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{56}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})$'
        self.ssdeep_regex = r'(?i)^[0-9]+:[a-zA-Z0-9/+]{1,}:[a-zA-Z0-9/+]{1,}$'
        self.empty_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        self.empty_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        self.empty_sha224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        self.empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.empty_sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        self.empty_sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        self.empty_ssdeep = "3::"

    def validate_ipv4(self, ip):
        """
        Validate an IPv4 address and determine its type.

        Parameters:
        ip (str): The IPv4 address to validate.

        Returns:
        tuple: The IP version (IPv4) and the type of the IP address (one of "Public", "Reserved", "Private", or None).
        """
        ip_type = None  # Initialize the type to None

        try:
            ip_address = ipaddress.IPv4Address(ip)
            if ip_address.is_private:
                ip_type = 'Private IPv4'
            elif ip_address.is_global:
                ip_type = 'Public IPv4'
            elif ip_address.is_reserved:
                ip_type = 'Reserved IPv4'
            elif ip_address.is_unspecified:
                ip_type = 'Unspecified IPv4'
            elif ip_address.is_loopback:
                ip_type = 'Loopback IPv4'
            elif ip_address.is_link_local:
                ip_type = 'Link-local IPv4'
            elif ip_address.is_multicast:
                ip_type = 'Multicast IPv4'
        except ipaddress.AddressValueError:
            # Address is not a valid IPv4 address
            pass

        return ip_type


    def validate_ipv6(self, ip):
        """
        Validate an IPv6 address and determine its type.

        Parameters:
        ip (str): The IPv6 address to validate.

        Returns:
        str: The type of the IPv6 address (one of "Public", "Reserved", "Private", "Unspecified", "Loopback", "Link-local", "Multicast", or None).
        """
        ip_type = None  # Initialize the type to None

        # Check if the IP address is in the correct format
        try:
            # Create an IPv6Address object
            ipv6_address = ipaddress.ip_address(ip)

            # Check various properties of the IPv6 address to determine its type
            if ipv6_address.is_private:
                ip_type = 'Private IPv6'
            elif ipv6_address.is_global:
                ip_type = 'Public IPv6'
            elif ipv6_address.is_reserved:
                ip_type = 'Reserved IPv6'
            elif ipv6_address.is_unspecified:
                ip_type = 'Unspecified IPv6'
            elif ipv6_address.is_loopback:
                ip_type = 'Loopback IPv6'
            elif ipv6_address.is_link_local:
                ip_type = 'Link-local IPv6'
            elif ipv6_address.is_multicast:
                ip_type = 'Multicast IPv6'
        except ValueError:
                    # Address is not a valid IPv4 address
                    pass

        return ip_type

    def get_ip_version(self, address):
        """
        Get the IP version of an IP address.

        Parameters:
        address (str): The IP address to check.

        Returns:
        str: The IP version ('IPv4', 'IPv6', or 'Unknown').
        """
        try:
            ip = ipaddress.ip_address(address)
            if ip.version == 4:
                return 'IPv4'
            elif ip.version == 6:
                return 'IPv6'
            else:
                return 'Unknown'
        except ValueError:
            return 'Invalid'

    def is_valid_ip_address(self, address):
        """
        Check if an IP address is valid.

        Parameters:
        address (str): The IP address to check.

        Returns:
        bool: True if the address is valid, False otherwise.
        """
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def validate_ip(self, ip):
        """
        Validate an IP address and determine its type.

        Parameters:
        ip (str): The IP address to validate.

        Returns:
        str: The type of the IP address ('Public', 'Reserved', 'Private', 'Unspecified', 'Loopback', 'Link-local', 'Multicast', or None).
        """
        ip_type = None

        if self.is_valid_ip_address(ip):
            ip_version = self.get_ip_version(ip)
            if ip_version == 'IPv4':
                ip_type = self.validate_ipv4(ip)
            elif ip_version == 'IPv6':
                ip_type = self.validate_ipv6(ip)
        return ip_type

    def validate_domain(self, domain):
        """
        Validate a domain and determine its type.

        Parameters:
        domain (str): The domain to validate.

        Returns:
        str: The type of the domain ('DOMAIN') if valid, otherwise None.
        """
        pattern = self.pattern_domain
        if pattern.match(domain):
            return "DOMAIN"
        else:
            return None

    def validate_hash(self, h):
        """
        Validate hash value and return hash type.

        Parameters:
        h (str): The hash value to validate.

        Returns:
        str: The type of the hash ('MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SSDEEP') if valid, otherwise None.
        """
        h = h.replace(" ", "")  # Remove whitespace from the hash value
        if isinstance(h, str):
            hash_length = len(h)
            if hash_length in {32, 40, 56, 64, 96, 128}:
                hash_types = {
                    32: "MD5",
                    40: "SHA-1",
                    56: "SHA-224",
                    64: "SHA-256",
                    96: "SHA-384",
                    128: "SHA-512",
                }
                return hash_types[hash_length]
            elif re.match(self.ssdeep_regex, h) and h != self.empty_ssdeep:
                return "SSDEEP"
        return None

    def validate_url(self, u):
        """
        Validate a URL and determine its type.

        Parameters:
        u (str): The URL to validate.

        Returns:
        str: The type of the URL ('URL') if valid, otherwise None.
        """
        if self.pattern_url.match(u):
            return "URL"
        return None