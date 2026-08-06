import os
import ipaddress
import re
import validators
import tldextract
from urllib.parse import urlparse, parse_qs
import socket


def get_service_name(port, protocol='tcp'):
    try:
        return socket.getservbyport(int(port), protocol)
    except (socket.error, ValueError):
        return None
    except Exception as e:
        return None

def get_port_from_service_name(service_name, protocol='tcp'):
    try:
        return socket.getservbyname(service_name, protocol)
    except (socket.error, ValueError):
        return None
    except Exception as e:
        return None

def extract_ip_address(text):
    match = re.search(r'IP Address:\s*([\d\.]+)', text)
    if match:
        return match.group(1)
    return None

def get_url_details(url):
    """
    Extracts comprehensive details from a URL including TLD, subdomain, scheme, resource path,
    query string, port, domain, and fragment.

    :param url: The URL to extract details from.
    :return: A dictionary containing detailed URL components.
    """
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)

    return {
        "scheme": parsed_url.scheme,
        "subdomain": extracted.subdomain,
        "domain": extracted.registered_domain,
        "tld": extracted.suffix,
        "port": parsed_url.port,
        "resource_path": parsed_url.path,
        "query_strings": parsed_url.query,
        "query_params": parse_qs(parsed_url.query),
        "fragment": parsed_url.fragment
    }


class DataValidator:
    """
    A robust class for validating IPs, domains, hashes, and URLs.
    Utilizes specialized libraries for improved accuracy.
    """

    def __init__(self):
        self.extractor = tldextract.TLDExtract(cache_dir="app/DataHandler/public", fallback_to_snapshot=True)
        # Regex patterns for additional validation
        self.ssdeep_regex = re.compile(r"(?i)^[0-9]+:[a-zA-Z0-9/+]{1,}:[a-zA-Z0-9/+]{1,}$")

    ### === IP VALIDATION === ###

    def validate_ip(self, ip: str) -> str | None:
        """
        Validates an IP address and determines its type.

        :param ip: The IP address to validate.
        :return: IP type (e.g., 'Public IPv4', 'Private IPv6') or None if invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(ip[0])
            ip_type = "IPv4" if ip_obj.version == 4 else "IPv6"

            if ip_obj.is_private:
                return f"Private {ip_type}"
            elif ip_obj.is_global:
                return f"Public {ip_type}"
            elif ip_obj.is_reserved:
                return f"Reserved {ip_type}"
            elif ip_obj.is_unspecified:
                return f"Unspecified {ip_type}"
            elif ip_obj.is_loopback:
                return f"Loopback {ip_type}"
            elif ip_obj.is_link_local:
                return f"Link-local {ip_type}"
            elif ip_obj.is_multicast:
                return f"Multicast {ip_type}"
        except ValueError:
            return None  # Invalid IP

    ### === DOMAIN VALIDATION === ###

    def validate_domain(self, domain: str) -> str | None:
        """
        Validates a domain.

        :param domain: The domain to validate.
        :return: 'DOMAIN' if valid, otherwise None.
        """
        # os.environ["HTTP_PROXY"] = os.getenv("PROXY")
        # os.environ["HTTPS_PROXY"] = os.getenv("PROXY")
        extracted = self.extractor(domain)
        if extracted.domain and extracted.suffix:
            return "DOMAIN"
        return None

    ### === HASH VALIDATION === ###

    def validate_hash(self, hash_str: str) -> str | None:
        """
        Validates a hash and identifies its type.

        :param h: The hash value.
        :return: The hash type (e.g., 'MD5', 'SHA-256', 'SSDEEP') or None if invalid.
        """
        hash_str = hash_str.strip().lower()
        if len(hash_str) == 32:
            return 'MD5'
        elif len(hash_str) == 40:
            return 'SHA-1'
        elif len(hash_str) == 64:
            return 'SHA-256'  # or verify further with actual checks
        elif self.ssdeep_regex.match(hash_str):
            return 'SSDEEP'
        return None


    ### === URL VALIDATION === ###

    def validate_url(self, url: str) -> str | None:
        """
        Validates a URL.

        :param url: The URL to validate.
        :return: 'URL' if valid, otherwise None.
        """
        return "URL" if validators.url(url) else None
