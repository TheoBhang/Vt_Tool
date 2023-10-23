import re                           # for working with regular expressions
import sys                          # for interacting with the Python interpreter
from collections import defaultdict # for creating a dictionary of values

class Pattern:
    """
    A collection of regular expression patterns for analyzing data.
    """

    # Regular expression pattern to match all valid IP address formats (IPv4 and IPv6)
    pattern_IP = re.compile(
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    # Regular expression pattern to match more variations of URLs
    pattern_URL = re.compile(
        r'(?:https?://|www\.)(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

    # Regular expression pattern to match the most popular hashes (MD5, SHA-1, SHA-256)
    pattern_Hash = re.compile(r'\b([a-fA-F0-9]{64})\b')

    # Regular expression pattern to match domain names
    pattern_Domain = re.compile(r'[a-z0-9-]{1,63}\.+[a-z]{2,63}')

    # Regular expression pattern to match filenames
    pattern_Filename = re.compile(r"\b(\w+)[-]?(\w+)?[-]?(\w+)?\.(7z|accdb|accde|activedirectory|adoc|ai|asciidoc|automatic|avi|awk|bat|bmp|bz2|c|class|cfg|cnf|coffee|conf|cpp|csv|dart|db|dbf|dit|dll|doc|docm|docx|dotm|dotx|eps|env|exe|fish|gif|go|graphql|graphqls|gql|gqls|gz|html|htm|hpp|ini|inf|iso|jar|java|jpeg|jpg|js|json|less|log|lua|markdown|md|mde|mkv|mov|mp3|mp4|odg|odp|ods|odt|ogv|one|onepkg|onetmp|onetoc|onetoc2|odc|odf|odft|odg|odi|odm|odp|ods|odt|ogg|ogv|old|one|onepkg|onetmp|onetoc|onetoc2|otg|otp|ots|ott|pdf|php|pl|png|potm|potx|ppam|ppsm|ppt|pptm|pptx|ps1|psd1|psm1|psd|pub|py|rar|rb|reg|rst|rs|rtf|rvices|.rvices|sass|scss|sed|sh|sldm|sql|stealthbits|svg|swift|sys|tar|tex|thmx|tif|tiff|toml|ts|tsx|ttf|txt|um|vb|vbs|vcd|vsdx|vssx|vstx|wav|webm|wmv|woff|woff2|xls|xlsx|xlsm|xltm|xml|xps|yaml|yml|zip)\b")

    # Regular expression pattern to match API keys that are alphanumeric and have a length of 32 characters or more
    pattern_API = re.compile(r'[a-zA-Z\d]{32}$')


class ValueReader:
    """
    
    A class for reading values from standard input, a file, or the user.
    
        Attributes:
        
            fname (str): The name of the file to read values from.
            values (dict): A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
                           corresponding to these keys are lists of extracted values from the file.
            dictValues (dict): A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
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
        self.dictValuesFile = defaultdict(list)
        self.dictValues = defaultdict(list)

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
        # Create a dictionary to store the extracted values
        if is_file:
            values_dict = self.dictValuesFile
        else:
            values_dict = self.dictValues

        # Extract IP addresses
        ips = Pattern.pattern_IP.findall(value)
        # Extract URLs
        urls = Pattern.pattern_URL.findall(value)
        # Extract hashes
        hashes = Pattern.pattern_Hash.findall(value)
        # Extract domains
        domains = Pattern.pattern_Domain.findall(value)
        # Extract API keys
        keys = Pattern.pattern_API.findall(value)

        # Add extracted values to the dictionary
        values_dict['ips'].extend(ips)
        values_dict['urls'].extend(urls)
        values_dict['hashes'].extend(hashes)
        for domain in domains:
            #if domain does not match a filename
            if not Pattern.pattern_Filename.match(domain.lower()) and "www" not in domain.lower():
                values_dict['domains'].append(domain)
        values_dict['keys'].extend(keys)

        # Add extracted values to the appropriate dictionary based on whether the input is a file or not
        if is_file:
            self.dictValuesFile.update(values_dict)
            return self.dictValuesFile
        else:
            self.dictValues.update(values_dict)
            return self.dictValues
        

    def read_from_stdin(self):
        """
        Read lines from standard input.

        Returns:
            List[str]: The lines read from standard input.

        Raises:
            ValueError: If standard input is closed.
        """
        if sys.stdin.isatty():  # Check if standard input is a terminal
            return {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}
        elif sys.stdin.closed:  # Check if standard input is closed
            raise ValueError("Standard input is closed")  # Raise an error
        else:
            # If standard input is open, read lines and return them as a list
            for line in sys.stdin:
                self.sort_values(line)
            return self.dictValues

    def read_from_file(self):
        """
        Read values from a file.

        Returns:
        dict: A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
              corresponding to these keys are lists of extracted values from the file.
        """
        try:
            if self.fname is not None:  # Only proceed if there is a file name
                with open(self.fname, encoding="utf8") as f:  # Open file
                    for line in f:  # Iterate through each line in the file
                        self.sort_values(line,is_file=True)  # Extract values from the line
                # Print success message
                print(f"Successfully read values from {self.fname}")
                return self.dictValuesFile
            
            else:
                # Print error message if no file name is provided
                print("No file name provided")

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
            values = {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}
        for value in self.values:
            self.sort_values(value,is_file=None)
        inputValues = self.dictValues
        # Read values from file
        file_values = self.read_from_file()
        if file_values is None:
            file_values = {"ips": [], "urls": [], "hashes": [], "keys": [], "domains": []}

        # Combine values and file_values
        combined_values = defaultdict(list)
        for key in values.keys():
            combined_values[key] = values[key] + inputValues[key] + file_values[key]

        # Remove duplicates and None values
        for key in combined_values.keys():
            combined_values[key] = list(set(filter(None, combined_values[key])))

        # Extract domain values
        domains = combined_values['domains']
        combined_values['domains'] = [domain for domain in domains if not Pattern.pattern_Filename.match(domain.lower()) and "www" not in domain.lower()]

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
