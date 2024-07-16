import re  # for working with regular expressions
import sys  # for interacting with the Python interpreter
from collections import defaultdict  # for creating a dictionary of values
from dataclasses import dataclass
from typing import Dict, List
from typing import Pattern as RePattern


@dataclass(frozen=True)
class Pattern:
    """
    A collection of regular expression patterns for analyzing data.
    """

    PATTERN_IP: RePattern = re.compile(
        r"(?:^|\s)((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"(?:(?:[0-9a-fA-F]{1,4}:){1,6}|:):(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:\s|$)"
    )
    PATTERN_URL: RePattern = re.compile(
        r"(?:https?://|www\.)"  # Protocol (http://, https://, or www.)
        r"(?:[\da-z\.-]+)\.[a-z]{2,6}"  # Domain name
        r"(?::\d{1,5})?"  # Port (optional)
        r"(?:/[^\s]*)?"  # Path (optional)
    )
    PATTERN_HASH: RePattern = re.compile(
        r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    )
    PATTERN_DOMAIN: RePattern = re.compile(
        r"(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    PATTERN_FILENAME: RePattern = re.compile(
        r"\b\w+(?:-\w+)*\.(?:7z|accdb|accde|activedirectory|adoc|ai|asciidoc|automatic|avi|awk|bat|bmp|bz2|c|class|cfg|cnf|coffee|conf|cpp|csv|dart|db|dbf|dit|dll|doc|docm|docx|dotm|dotx|eps|env|exe|fish|gif|go|graphql|graphqls|gql|gqls|gz|html|htm|hpp|ini|inf|iso|jar|java|jpeg|jpg|js|json|less|log|lua|markdown|md|mde|mkv|mov|mp3|mp4|odg|odp|ods|odt|ogv|one|onepkg|onetmp|onetoc|onetoc2|odc|odf|odft|odg|odi|odm|odp|ods|odt|ogg|ogv|old|one|onepkg|onetmp|onetoc|onetoc2|otg|otp|ots|ott|pdf|php|pl|png|potm|potx|ppam|ppsm|ppt|pptm|pptx|ps1|psd1|psm1|psd|pub|py|q2k|rar|rb|reg|rst|rs|rtf|rvices|sass|scss|sed|sh|sldm|sql|stealthbits|svg|swift|sys|tar|tex|thmx|tif|tiff|toml|ts|tsx|ttf|txt|um|vb|vbs|vcd|vsdx|vssx|vstx|wav|webm|wmv|woff|woff2|xls|xlsx|xlsm|xltm|xml|xps|yaml|yml|zip)\b"
    )
    PATTERN_REMOVE: RePattern = re.compile(r"(?:[0-9.]{1,256}\.[0-9]{1,6}\b)(?:[0-9]*)")
    PATTERN_API: RePattern = re.compile(r"[a-zA-Z\d]{32,}$")

    def match_ip(self, text: str) -> List[str]:
        """Match IP addresses in the given text."""
        return self.PATTERN_IP.findall(text)

    def match_url(self, text: str) -> List[str]:
        """Match URLs in the given text."""
        return self.PATTERN_URL.findall(text)

    def match_hash(self, text: str) -> List[str]:
        """Match hashes in the given text."""
        return self.PATTERN_HASH.findall(text)

    def match_domain(self, text: str) -> List[str]:
        """Match domain names in the given text."""
        return self.PATTERN_DOMAIN.findall(text)

    def match_filename(self, text: str) -> List[str]:
        """Match filenames in the given text."""
        return self.PATTERN_FILENAME.findall(text)

    def match_api(self, text: str) -> List[str]:
        """Match API keys in the given text."""
        return self.PATTERN_API.findall(text)


class ValueExtractor:
    def __init__(self):
        # Initialize with pattern constants from Pattern class
        self.pattern_api = Pattern.PATTERN_API
        self.pattern_domain = Pattern.PATTERN_DOMAIN
        self.pattern_filename = Pattern.PATTERN_FILENAME
        self.pattern_hash = Pattern.PATTERN_HASH
        self.pattern_ip = Pattern.PATTERN_IP
        self.pattern_url = Pattern.PATTERN_URL

        # Dictionaries to store extracted values
        self.dict_values: Dict[str, List[str]] = {
            "ips": [],
            "urls": [],
            "hashes": [],
            "domains": [],
            "keys": [],
        }
        self.dict_values_file: Dict[str, List[str]] = {
            "ips": [],
            "urls": [],
            "hashes": [],
            "domains": [],
            "keys": [],
        }

    def sort_values(self, value: str, is_file: bool) -> Dict[str, List[str]]:
        """
        Extract values from a string or file.

        Parameters:
        value (str): The string (or file content) to extract values from.
        is_file (bool): Indicates whether the input is a file (True) or a string (False).

        Returns:
        dict: A dictionary with keys 'ips', 'urls', 'hashes', 'domains', and 'keys' containing lists of extracted values.
        """
        values_dict = self.dict_values_file if is_file else self.dict_values

        # Extract values using regular expressions
        values_dict["ips"].extend(self.pattern_ip.findall(value))
        values_dict["urls"].extend(self.pattern_url.findall(value))
        values_dict["hashes"].extend(self.pattern_hash.findall(value))
        values_dict["domains"].extend(self.pattern_domain.findall(value))
        values_dict["keys"].extend(self.pattern_api.findall(value))

        # Clean up domain names
        values_dict["domains"] = [
            domain.replace("www.", "") for domain in values_dict["domains"]
        ]
        values_dict["domains"] = [
            domain
            for domain in values_dict["domains"]
            if not self._matches_filename(domain)
        ]

        # Update class dictionaries with extracted values
        if is_file:
            self.dict_values_file = values_dict
        else:
            self.dict_values = values_dict

        return values_dict

    def _matches_filename(self, domain: str) -> bool:
        """
        Check if a domain matches a filename pattern.

        Parameters:
        domain (str): The domain name to check.

        Returns:
        bool: True if the domain matches the filename pattern, False otherwise.
        """
        return bool(self.pattern_filename.match(domain.lower()))


class ValueReader:
    """
    A class for reading values from standard input, a file, or the user.

    Attributes:
        fname (str): The name of the file to read values from.
        dict_values (dict): A dictionary with keys 'ips', 'urls', 'hashes', and 'keys'. The values
                            corresponding to these keys are lists of extracted values.
    """

    def __init__(self, fname, values):
        self.fname = fname
        self.values = values
        self.dict_values_file = defaultdict(list)
        self.dict_values = defaultdict(list)

    def read_from_stdin(self) -> dict:
        """
        Read values from standard input.

        Returns:
            dict: A dictionary with keys 'ips', 'urls', 'hashes', 'keys', and 'domains'. The values
                  corresponding to these keys are lists of extracted values.
        """
        # Check if standard input is a terminal
        if sys.stdin.isatty():
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}
        elif sys.stdin.closed:  # Check if standard input is closed
            raise ValueError("Standard input is closed")  # Raise an error
        else:
            # Create a new ValueExtractor instance
            value_extractor = ValueExtractor()
            # Read lines from standard input
            for line in sys.stdin:
                # Sort values from each line
                line_values = value_extractor.sort_values(line, is_file=False)
                # Merge the values from the current line with the accumulated values
                for key, values in line_values.items():
                    self.dict_values[key].extend(values)
            # Return the accumulated values
            print("Successfully read values from user input")
            return self.dict_values


    def read_from_file(self):
        """
        Read values from a file.

        Returns:
        dict: A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
            corresponding to these keys are lists of extracted values from the file.
        """
        # Check if a file name is provided
        if self.fname is None:
            print("No file name provided")
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

        value_extractor = ValueExtractor()
        try:
            with open(self.fname, encoding="utf8") as f:  # Open file
                for line in f:  # Iterate through each line in the file
                    # Sort values from each line
                    line_values = value_extractor.sort_values(line, is_file=True)
                    # Merge the values from the current line with the accumulated values
                    for key, values in line_values.items():
                        self.dict_values_file[key].extend(values)
            # Print success message
            print(f"Successfully read values from {self.fname}")
            return self.dict_values_file

        except FileNotFoundError:
            # Print error message if the file is not found
            print(f"File {self.fname} not found")
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

        except IOError as e:  # Catch IOError if there is a problem reading the file
            # Print error message
            print(f"I/O error({e.errno}): {e.strerror}")

    def read_values(self):
        """
        Read values from standard input and file, remove duplicates and None values.

        Returns:
        dict: A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
              corresponding to these keys are lists of extracted values from the user.
        """
        # Read values from standard input
        values = self.read_from_stdin() 
        if values is None:
            values = defaultdict(list)

        # Read values from file
        file_values = self.read_from_file()

        # Combine values and file_values
        combined_values = defaultdict(list)
        for key in values.keys():
            combined_values[key] = values[key] + self.dict_values[key] + file_values[key]

        # Remove duplicates and None values
        for key in combined_values.keys():
            combined_values[key] = list(set(filter(None, combined_values[key])))

        # Extract domain values
        domains = combined_values['domains']
        combined_values['domains'] = [domain for domain in domains if not ValueExtractor()._matches_filename(domain)]

        # Create dictionary of results
        results = {
            "ips": combined_values['ips'],
            "urls": combined_values['urls'],
            "hashes": combined_values['hashes'],
            "domains": combined_values['domains'],
        }

        return results
