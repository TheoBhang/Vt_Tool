import re                           # for working with regular expressions
import sys                          # for interacting with the Python interpreter
from collections import defaultdict # for creating a dictionary of values

class Pattern:
    """
    A collection of regular expression patterns for analyzing data.
    """

    # Regular expression pattern to match all valid IP address formats (IPv4 and IPv6)
    pattern_ip = re.compile(
        r'(?:^|\s)((?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:(?:[0-9a-fA-F]{1,4}:){1,6}|:):(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:\s|$)'
    )

    pattern_url = re.compile(
        r'(?:https?://|www\.)'                 # Protocol (http://, https://, or www.)
        r'(?:[\da-z\.-]+)\.[a-z]{2,6}'          # Domain name
        r'(?::\d{1,5})?'                        # Port (optional)
        r'(?:/[^\s]*)?'                         # Path (optional)
    )
    # Regular expression pattern to match the most popular hashes (MD5, SHA-1, SHA-256)
    pattern_hash = re.compile(
        r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
    )

    # Regular expression pattern to match domain names
    pattern_domain = re.compile(
        r'(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    # Regular expression pattern to match filenames
    pattern_filename = re.compile(
        r'\b\w+(?:-\w+)*\.(?:7z|accdb|accde|activedirectory|adoc|ai|asciidoc|automatic|avi|awk|bat|bmp|bz2|c|class|cfg|cnf|coffee|conf|cpp|csv|dart|db|dbf|dit|dll|doc|docm|docx|dotm|dotx|eps|env|exe|fish|gif|go|graphql|graphqls|gql|gqls|gz|html|htm|hpp|ini|inf|iso|jar|java|jpeg|jpg|js|json|less|log|lua|markdown|md|mde|mkv|mov|mp3|mp4|odg|odp|ods|odt|ogv|one|onepkg|onetmp|onetoc|onetoc2|odc|odf|odft|odg|odi|odm|odp|ods|odt|ogg|ogv|old|one|onepkg|onetmp|onetoc|onetoc2|otg|otp|ots|ott|pdf|php|pl|png|potm|potx|ppam|ppsm|ppt|pptm|pptx|ps1|psd1|psm1|psd|pub|py|q2k|rar|rb|reg|rst|rs|rtf|rvices|sass|scss|sed|sh|sldm|sql|stealthbits|svg|swift|sys|tar|tex|thmx|tif|tiff|toml|ts|tsx|ttf|txt|um|vb|vbs|vcd|vsdx|vssx|vstx|wav|webm|wmv|woff|woff2|xls|xlsx|xlsm|xltm|xml|xps|yaml|yml|zip)\b'
    )
    pattern_remove = re.compile(r'(?:[0-9.]{1,256}\.[0-9]{1,6}\b)(?:[0-9]*)')
    # Regular expression pattern to match API keys that are alphanumeric and have a length of 32 characters or more
    pattern_api = re.compile(r'[a-zA-Z\d]{32,}$')


class ValueExtractor:
    def __init__(self):
        # Define regular expression patterns as class attributes
        self.pattern_api = Pattern.pattern_api
        self.pattern_domain = Pattern.pattern_domain
        self.pattern_filename = Pattern.pattern_filename
        self.pattern_hash = Pattern.pattern_hash
        self.pattern_ip = Pattern.pattern_ip
        self.pattern_url = Pattern.pattern_url
        

        # Initialize dictionaries to store extracted values
        self.dict_values = {
            'ips': [],
            'urls': [],
            'hashes': [],
            'domains': [],
            'keys': []
        }
        self.dict_values_file = {
            'ips': [],
            'urls': [],
            'hashes': [],
            'domains': [],
            'keys': []
        }

    def sort_values(self, value, is_file):
        """
        Extract values from a string.

        Parameters:
        value (str): The string to extract values from.
        is_file (bool): Whether the input is a file or not.

        Returns:
        dict: A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
              corresponding to these keys are lists of extracted values from the string.
        """
        # Select appropriate dictionary based on is_file flag
        values_dict = self.dict_values_file if is_file else self.dict_values

        # Extract values using regular expressions
        values_dict['ips'].extend(self.pattern_ip.findall(value))
        values_dict['urls'].extend(self.pattern_url.findall(value))
        values_dict['hashes'].extend(self.pattern_hash.findall(value))
        values_dict['domains'].extend(self.pattern_domain.findall(value))
        values_dict['keys'].extend(self.pattern_api.findall(value))

        # Remove 'www.' from domain names if present
        values_dict['domains'] = [domain.replace("www.", "") for domain in values_dict['domains']]

        # Filter out domain names that match filenames
        values_dict['domains'] = [domain for domain in values_dict['domains'] if not self._matches_filename(domain)]

        # Update class dictionaries with extracted values
        if is_file:
            self.dict_values_file = values_dict
        else:
            self.dict_values = values_dict
        return values_dict

    def _matches_filename(self, domain):
        # Function to check if a domain matches a filename pattern
        return bool(self.pattern_filename.match(domain.lower()))


class ValueReader:
    """
    
    A class for reading values from standard input, a file, or the user.
    
        Attributes:
        
            fname (str): The name of the file to read values from.
            values (dict): A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
                           corresponding to these keys are lists of extracted values from the file.
            dict_values (dict): A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
                               corresponding to these keys are lists of extracted values from the file.
        Methods:
                                    
            sort_values(value): Extract values from a string.
            read_from_stdin(): Read values from standard input.
            read_from_file(): Read values from a file.
            read_values(): Read values from the user.
                                
    """

    def __init__(self, fname, values):
        self.fname = fname
        self.values = values
        self.dict_values_file = defaultdict(list)
        self.dict_values = defaultdict(list)

    def read_from_stdin(self):
        """
        Read lines from standard input.

        Returns:
            List[str]: The lines read from standard input.

        Raises:
            ValueError: If standard input is closed.
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
            "ip_duplicates": values['ips'] + file_values['ips'],
            "url_duplicates": values['urls'] + file_values['urls'],
            "hash_duplicates": values['hashes'] + file_values['hashes'],
            "domain_duplicates": values['domains'] + file_values['domains']
        }

        return results
