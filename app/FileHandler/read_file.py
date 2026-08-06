import os  # for interacting with the operating system
import re  # for working with regular expressions
import sys  # for interacting with the Python interpreter
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Dict, List
from typing import Pattern as RePattern


@dataclass(frozen=True)
class Pattern:
    """
    A collection of regular expression patterns for analyzing data.
    """

    # Regular expressions for matching different types of data
    PATTERN_IP: RePattern = re.compile(
        r"(?:^|\s)((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        r"(?:(?:[0-9a-fA-F]{1,4}:){1,6}|:):(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|"
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:\s|$)"
    )
    PATTERN_IP_PORT: RePattern = re.compile(
        r"(?:^|\s)("
            r"(?:"
                r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
                r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
                r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
                r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|"
                r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|"
                # IPv4
                r"(?:\d{1,3}\.){3}\d{1,3}"
            r")"
            r")"
            r"(?::(\d{1,5}))?"  # Optional port
            r"(?=\s|$)"         # Lookahead for whitespace or end-of-line
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
    PATTERN_API: RePattern = re.compile(r"[a-zA-Z\d]{32,}$")

    def match_pattern(self, text: str, pattern_type: str) -> List[str]:
        """Match patterns based on the pattern type."""
        patterns = {
            'ip': self.PATTERN_IP_PORT,
            'url': self.PATTERN_URL,
            'hash': self.PATTERN_HASH,
            'domain': self.PATTERN_DOMAIN,
            'filename': self.PATTERN_FILENAME,
            'api': self.PATTERN_API
        }

        pattern = patterns.get(pattern_type)

        if pattern:
            return pattern.findall(text)
        else:
            raise ValueError(f"Pattern type '{pattern_type}' is not supported.")

    def match_all_patterns(self, text: str) -> Dict[str, List[str]]:
        """Match all patterns in the provided text and return a dictionary of matches."""
        matches = defaultdict(list)

        for pattern_name in ['ip', 'url', 'hash', 'domain', 'filename', 'api']:
            matches[pattern_name] = self.match_pattern(text, pattern_name)

        return dict(matches)

    def match_pattern_count(self, text: str, pattern_type: str) -> Dict[str, int]:
        """Match a specific pattern and count occurrences."""
        matches = self.match_pattern(text, pattern_type)
        return Counter(matches)

    def match_all_patterns_count(self, text: str) -> Dict[str, int]:
        """Match all patterns and return a count of occurrences for each."""
        matches = self.match_all_patterns(text)
        return {key: len(value) for key, value in matches.items()}


class ValueExtractor:
    def __init__(self):
        # Initialize with an instance of Pattern class to use dynamic pattern matching
        self.pattern_instance = Pattern()

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

        # Extract values using the match_pattern method of the Pattern class
        values_dict["ips"].extend(self.pattern_instance.match_pattern(value, 'ip'))
        values_dict["urls"].extend(self.pattern_instance.match_pattern(value, 'url'))
        values_dict["hashes"].extend(self.pattern_instance.match_pattern(value, 'hash'))
        values_dict["domains"].extend(self.pattern_instance.match_pattern(value, 'domain'))
        values_dict["keys"].extend(self.pattern_instance.match_pattern(value, 'api'))

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
        # Using the match_filename pattern from the Pattern class
        return bool(self.pattern_instance.PATTERN_FILENAME.match(domain.lower()))

    def get_value_count(self, value: str, is_file: bool) -> Dict[str, int]:
        """
        Get the count of extracted values for each pattern type.

        Parameters:
        value (str): The string (or file content) to extract values from.
        is_file (bool): Indicates whether the input is a file (True) or a string (False).

        Returns:
        dict: A dictionary with counts of 'ips', 'urls', 'hashes', 'domains', and 'keys'.
        """
        values_dict = self.sort_values(value, is_file)

        # Count occurrences for each pattern type
        value_counts = {key: len(values) for key, values in values_dict.items()}

        return value_counts


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
        Read values from standard input and extract them using the ValueExtractor class.

        Returns:
            dict: A dictionary with keys 'ips', 'urls', 'hashes', 'keys', and 'domains'.
                  The values corresponding to these keys are lists of extracted values.
        """
        # Create a new ValueExtractor instance
        value_extractor = ValueExtractor()

        # Check if standard input is available and readable
        if sys.stdin.isatty() or sys.stdin.closed:
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

        try:
            # Read each line from stdin, process it, and accumulate extracted values
            for line in sys.stdin:
                line_values = self._process_line(line, value_extractor)
                self._accumulate_values(line_values)

            # Return the accumulated values after processing input
            print("Successfully read values from user input")
            return dict(self.dict_values)

        except Exception as e:
            # Catch any exceptions and provide useful feedback
            print(f"Error while reading from standard input: {e}")
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

    def _process_line(self, line: str, value_extractor: ValueExtractor) -> dict:
        """
        Extract values from a single line of input using the value extractor.

        Args:
            line (str): The line to process.
            value_extractor (ValueExtractor): The instance to extract values from the line.

        Returns:
            dict: A dictionary of extracted values ('ips', 'urls', 'hashes', 'keys', 'domains').
        """
        # Use the ValueExtractor to sort values for the line
        return value_extractor.sort_values(line, is_file=False)

    def _accumulate_values(self, line_values: dict):
        """
        Accumulate extracted values into the main dictionary.

        Args:
            line_values (dict): The values extracted from a single line.
        """
        for key, values in line_values.items():
            self.dict_values[key].extend(values)

    def read_from_file(self) -> dict:
        """
        Read values from a file and extract them using the ValueExtractor class.

        Returns:
            dict: A dictionary with keys 'ips', 'urls', 'hashes', 'keys', and 'domains'.
                  The values corresponding to these keys are lists of extracted values from the file.
        """
        # Check if the filename is provided
        if not self.fname:
            print("No file name provided")
            return self._get_empty_values()

        # Check if the file exists
        if not os.path.isfile(self.fname):
            print(f"File {self.fname} does not exist")
            return self._get_empty_values()

        try:
            # Create an instance of ValueExtractor
            value_extractor = ValueExtractor()

            # Read file and extract values
            self._process_file_lines(value_extractor)

            # Return accumulated values
            return dict(self.dict_values_file)

        except (IOError, Exception) as e:
            # Catch any I/O or unexpected errors
            print(f"Error reading file {self.fname}: {e}")
            return self._get_empty_values()
        
    def read_from_csv_file(self) -> dict:
        """
        Read values from a CSV file and extract them using the ValueExtractor class.

        Returns:
            dict: A dictionary with keys 'ips', 'urls', 'hashes', 'keys', and 'domains'.
                  The values corresponding to these keys are lists of extracted values from the file.
        """
        # Check if the filename is provided
        if not self.fname:
            print("No file name provided")
            return self._get_empty_values()

        # Check if the file exists
        if not os.path.isfile(self.fname):
            print(f"File {self.fname} does not exist")
            return self._get_empty_values()

        try:
            exit("CSV file reading not implemented yet")

        except (IOError, Exception) as e:
            # Catch any I/O or unexpected errors
            print(f"Error reading file {self.fname}: {e}")
            return self._get_empty_values

    def _process_file_lines(self, value_extractor: ValueExtractor):
        """
        Process each line from the file and extract values using the ValueExtractor.

        Args:
            value_extractor (ValueExtractor): The instance to extract values from each line.
        """
        with open(self.fname, encoding="utf8") as file:
            for line in file:
                line_values = value_extractor.sort_values(line, is_file=True)
                self._accumulate_file_values(line_values)

    def _accumulate_file_values(self, line_values: dict):
        """
        Accumulate the extracted values into the dictionary.

        Args:
            line_values (dict): The values extracted from a single line of the file.
        """
        for key, values in line_values.items():
            self.dict_values_file[key].extend(values)

    def _get_empty_values(self):
        """
        Returns a dictionary with empty lists for 'ips', 'urls', 'hashes', 'keys', and 'domains'.
        """
        return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

    def read_template_values(self,template) -> dict:
        """
        Read values from standard input and file, remove duplicates and None values, 
        and extract domains. Returns a dictionary with the extracted values.

        Returns:
            dict: A dictionary with 'ips', 'urls', 'hashes', 'domains' as keys, each
                  containing a list of unique extracted values.
        """
        # Read values from standard input and file
        stdin_values = self.read_from_stdin()
        file_values = self.read_from_csv_file()

        # Combine values and remove duplicates and None values
        combined_values = self._combine_and_clean_values(stdin_values, file_values)

        # Return the final cleaned dictionary
        return self._extract_and_filter_domains(combined_values)

    def read_values(self) -> dict:
        """
        Read values from standard input and file, remove duplicates and None values, 
        and extract domains. Returns a dictionary with the extracted values.

        Returns:
            dict: A dictionary with 'ips', 'urls', 'hashes', 'domains' as keys, each
                  containing a list of unique extracted values.
        """
        # Read values from standard input and file
        stdin_values = self.read_from_stdin()
        file_values = self.read_from_file()

        # Combine values and remove duplicates and None values
        combined_values = self._combine_and_clean_values(stdin_values, file_values)

        # Return the final cleaned dictionary
        return self._extract_and_filter_domains(combined_values)

    def _combine_and_clean_values(self, stdin_values: dict, file_values: dict) -> dict:
        """
        Combine the values from stdin and file, remove duplicates, and clean the lists.

        Args:
            stdin_values (dict): The extracted values from standard input.
            file_values (dict): The extracted values from the file.

        Returns:
            dict: A dictionary with keys 'ips', 'urls', 'hashes', 'keys', and 'domains',
                  containing the merged and cleaned values.
        """
        # Merge values from stdin and file and deduplicate
        combined_values = defaultdict(list)
        for key in stdin_values.keys():
            combined_values[key] = list(set(stdin_values[key] + file_values[key]))

        # Remove None values from the lists
        return {key: list(filter(None, values)) for key, values in combined_values.items()}

    def _extract_and_filter_domains(self, combined_values: dict) -> dict:
        """
        Extract and filter domain values, removing those that match filename patterns.

        Args:
            combined_values (dict): The combined and cleaned dictionary of values.

        Returns:
            dict: The dictionary with domain values filtered.
        """
        # Extract and filter domain values
        domains = combined_values['domains']
        combined_values['domains'] = [
            domain for domain in domains if not ValueExtractor()._matches_filename(domain)
        ]

        # Return the cleaned dictionary with domains filtered
        return {key: combined_values[key] for key in ['ips', 'urls', 'hashes', 'domains']}