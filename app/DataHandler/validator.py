import re
import ipaddress
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

    def validate_ipv4(ip):
        """
        Validate an IPv4 address and determine its type.

        Parameters:
        ip (str): The IPv4 address to validate.

        Returns:
        tuple: The IP version (IPv4) and the type of the IP address (one of "Public", "Reserved", "Private", or None).
        """
        ip_type = None  # Initialize the type to None

        # Check if the IP address is in the correct format
        if Pattern.pattern_IP.match(ip):
            if ipaddress.ip_address(ip).is_private:
                ip_type = 'Private IPv4'
            if ipaddress.ip_address(ip).is_global:
                ip_type = 'Public IPv4'
            if ipaddress.ip_address(ip).is_reserved:
                ip_type = 'Reserved IPv4'
            if ipaddress.ip_address(ip).is_unspecified:
                ip_type = 'Unspecified IPv4'
            if ipaddress.ip_address(ip).is_loopback:
                ip_type = 'Loopback IPv4'
            if ipaddress.ip_address(ip).is_link_local:
                ip_type = 'Link-local IPv4'
            if ipaddress.ip_address(ip).is_multicast:
                ip_type = 'Multicast IPv4'

        return (ip_type)


    def validate_ipv6(ip):
        """
        Validate an IPv6 address and determine its type.

        Parameters:
        ip (str): The IPv6 address to validate.

        Returns:
        tuple: The IP version (IPv6) and the type of the IP address (one of "Public", "Reserved", "Private", or None).
        """
        ip_type = None  # Initialize the type to None

        # Check if the IP address is in the correct format
        if Pattern.pattern_IP.match(ip):
            if ipaddress.ip_address(ip).is_private:
                ip_type = 'Private IPv6'
            if ipaddress.ip_address(ip).is_global:
                ip_type = 'Public IPv6'
            if ipaddress.ip_address(ip).is_reserved:
                ip_type = 'Reserved IPv6'
            if ipaddress.ip_address(ip).is_unspecified:
                ip_type = 'Unspecified IPv6'
            if ipaddress.ip_address(ip).is_loopback:
                ip_type = 'Loopback IPv6'
            if ipaddress.ip_address(ip).is_link_local:
                ip_type = 'Link-local IPv6'
            if ipaddress.ip_address(ip).is_multicast:
                ip_type = 'Multicast IPv6'

        return (ip_type)

    def get_ip_version(address):
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

    def is_valid_ip_address(address):
        try:
            ip = ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def validate_ip(self,ip):
        """
        Validate an IP address and determine its type.

        Parameters:
        ip (str): The IP address to validate.

        Returns:
        str: The type of the IP address (one of "Public", "Reserved", or None).
        """
        ip_type = None  # Initialize the type to None

        # Check if the IP address is in the correct format
        if self.is_valid_ip_address(ip):
            if self.get_ip_version(ip) == 'IPv4':
                ip_type = self.validate_ipv4(ip)
            elif self.get_ip_version(ip) == 'IPv6':
                ip_type = self.validate_ipv6(ip)
                
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
            r'(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        )

        # Check if the domain is in the correct format
        if pattern.match(domain):
            domain_type = "DOMAIN"  # Set the type to "DOMAIN

        return domain_type  # Return the type

    def validate_hash(h, ipv6_addresses):
        """Validate hash value and return hash type"""
        hash_type = None
        h = h.replace(" ", "")
        # Check if the input is a string
        if isinstance(h, str):
            # Use a single regular expression to match all types of hash values
            hash_regex = r'(?i)^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{56}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})$'
            ssdeep_regex = r'(?i)^[0-9]+:[a-zA-Z0-9/+]{1,}:[a-zA-Z0-9/+]{1,}$'
            empty_md5 = "d41d8cd98f00b204e9800998ecf8427e"
            empty_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            empty_sha224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
            empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            empty_sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            empty_sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            empty_ssdeep = "3::"
            if re.match(hash_regex, h) and h not in [empty_md5, empty_sha1, empty_sha224, empty_sha256, empty_sha384, empty_sha512]:
                # Determine the type of hash by checking the length of the input string
                hash_types = {
                    32: "MD5",
                    40: "SHA-1",
                    56: "SHA-224",
                    64: "SHA-256",
                    96: "SHA-384",
                    128: "SHA-512",
                }
                hash_length = len(h)
                if hash_length in hash_types:
                    hash_type = hash_types[hash_length]
            elif re.match(ssdeep_regex, h) and h != empty_ssdeep:
                for i in ipv6_addresses:
                    if h in i:
                        print("IPv6 address detected as ssdeep hash value: {}".format(h))
                        hash_type = None
                        break
                    else:
                        hash_type = "SSDEEP"

        return hash_type

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