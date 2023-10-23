<p align="center">
    <img src="assets/logo.png" alt= “VirusTotal_tool_logo” width="250" height="250">
</p>

# THA-CERT VirusTotal Analysis Tool Documentation

Welcome to the VirusTotal analysis tool by THA-CERT !

This script will retrieve analysis information for a set of values (IP/Hash/URL) from VirusTotal.

To use the tool, provide your VirusTotal API key and the values you want to analyze.

The tool supports input from two sources, files and command line.

## What goals ?

This tool is used to search files or/and input with RegEx to find Objects(IP adresses, Hashes and Urls) and ask VirusTotal for a report if the Object was already submitted. If not it won't submit it for review.

The goal is to make easier and faster analysis on files such as log files or other files encountered while investigating.

All you have to do is follow the guide and then grab a coffee while waiting for your analysis to be done !

All results will be sorted by Objects category and on two files, one is a txt containing a condensed version of a VT report helping people getting only interesting results. And the other is a CSV file, that can be translated to JSON to help sending the data , to MISP, Strangebee's The Hive or others.

Then if you want you could send all the results to MISP by following the script options, and by default using the docker image.

## How to use ?

### Installation

To install and run VT_Tools, you will need to have python 3.9 or more installed on your system.

- Clone the repository:
  - git clone <https://github.com/TheoBhang/Analysis_Tool>
- Install all depedencies with:
  - pip install -r requirements.txt

Then the script should be ready to launch

### Usage

#### Locally

```md
usage: vt3_tools.py [-h] [--input_file INPUT_FILE] [--case_id CASE_ID] [--api_key API_KEY]
                    [--api_key_file API_KEY_FILE] [--proxy PROXY]
                    [values ...]

positional arguments:
  values                The values to analyze. Can be IP addresses, hashes, URLs, or domains.

options:
  -h, --help            show this help message and exit
  --input_file INPUT_FILE, -f INPUT_FILE
                        Input file containing values to analyze.
  --case_id CASE_ID, -c CASE_ID
                        Id for the case to create
  --api_key API_KEY, -a API_KEY
                        VirusTotal API key, default VTAPIKEY env var.
  --api_key_file API_KEY_FILE, -af API_KEY_FILE
                        VirusTotal API key in a file.
  --proxy PROXY, -p PROXY
                        Proxy to use for requests.
```

And run :

```sh
# For any help just launch
python3 .\vt3_tools.py -h

# By Default if you don't specify a VT API key the script will search in the environment variables.
python3 .\vt3_tools.py --case_id <Case ID> [INPUT_VALUE]

# For Input based analysis with an API KEY:
python3 .\vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> [INPUT_VALUE]

# For File based analysis:
python3 .\vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> --input_file <Path to file>

# You can also use your api key from a file:
python3 .\vt3_tools.py --api_key_file <Path to APIKEY file> --case_id <Case ID> --input_file <Path to file>

# if you have to use a proxy to connect to the internet you can use the --proxy option
python3 .\vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> --input_file <Path to file> --proxy <Proxy URL>
```

#### Docker

To use VT Tools with docker you have to:

- clone the repo, change your .env file and build the image from the Dockerfile with the command:

```sh
docker build -t vt3_tools .
```

Then to launch the script via Docker you have to:

- Put yourself in the right Folder
- Create two folder, one for the Results and one for the files you want to submit.

For example:

```txt
|| ./VT-tools
|| Files
||  ==> # Files you want to submit
|| Results
||  ==> # Where the result will be saved
```

Once they are created, put the file you want to submit in the Files folder and then if it is not already done, open a terminal based on the main folder containing the Dockerfile.

And run :

```sh
# For any help just launch
docker run -v ${pwd}/Results:/vt/Results/ -v ${pwd}/Files:/vt/files/ --network host --name vt_tools2misp --rm --name vt_tools vt3_tools:latest

# If you want to use a .env in your local instance you will have to rebuild the image after modifying the env
# By Default if you don't specify a VT API key the script will search in the environment variables.
docker run \
-v ${pwd}/Results:/vt/Results/ \
-v ${pwd}/Files:/vt/files/ \
--network host --name vt_tools2misp \
--rm --name vt_tools vt3_tools:latest  \ 
--input_file <Container Path to file> \
--case_id <Case ID>

# For Input based analysis
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
--network host --name vt_tools2misp \
--rm --name vt_tools vt3_tools:latest \ 
--api_key <Your VT APIKEY> \ 
[INPUT_VALUE] \ 
--case_id <Case ID>

# For File based analysis
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
--network host --name vt_tools2misp \
--rm --name vt_tools vt3_tools:latest \ 
--api_key <Your VT APIKEY> \ 
--input_file <Container Path to file>  \ 
--case_id <Case ID>

# You can also use your api key from a file for this put the file in your previously created Files folder and use:
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
--network host --name vt_tools2misp \
--rm --name vt_tools vt3_tools:latest \ 
--api_key_file <Container Path to api key file> \ 
--input_file <Container Path to file>  \ 
--case_id <Case ID>

```

## Involved dependencies

- click
- prettytable
- setuptools
- vt-py
- python-dotenv
- pymisp
- urllib3

## Code Explaining

The vt_tools2misp was made using script from the github MISP Repository for more informations :

- <https://github.com/MISP/PyMISP>

### Library used

```python
re            # for working with regular expressions
sys           # for interacting with the Python interpreter
time          # for creating countdown timers
os            # for interacting with the operating system
vt            # for interacting with VirusTotal API V3
collections   # for creating a dictionary of values
prettytable   # for formatting results in a table
argparse      # for parsing command line arguments
datetime      # for getting the current date and time
logging       # for logging the script's activity
dotenv        # for loading environment variables
csv           # for interacting with CSV files
typing        # for defining types of variables
```

---

### Class

#### Pattern Class

The Patern Class is used to store every pattern in our script.

The pattern correspond to Regular Expressions for IP, Domains, SHA 256 Hashes and URL.

```python
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
```

---

#### Reading values Class

```python
class ValueReader:
    """
    
    A class for reading values from standard input, a file, or the user.
    
        Attributes:
        
            fname (str): The name of the file to read values from.
            values (dict): A dictionary with five keys: 'ips', 'urls', 'hashes', 'domains' and 'keys'. The values
                           corresponding to these keys are lists of extracted values from the file.
            dictValues (dict): A dictionary with five keys: 'ips', 'urls', 'hashes', 'domains' and 'keys'. The values
                               corresponding to these keys are lists of extracted values from the file.
        Methods:
                                    
            sort_values(value): Extract values from a string.
            read_from_stdin(): Read values from standard input.
            read_from_file(): Read values from a file.
            read_values(): Read values from the user.
                                
    """

    def __init__(self, fname, values):
        self.fname = fname
        if values is None:
            self.values = defaultdict(list)
        else:
            self.values = values
        self.dictValues = defaultdict(list)

    def sort_values(self,value):
        """
        Extract values from a string.

        Parameters:
        value (str): The string to extract values from.

        Returns:
        dict: A dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
              corresponding to these keys are lists of extracted values from the string.

        """
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
        self.dictValues['ips'].extend(ips)
        self.dictValues['urls'].extend(urls)
        self.dictValues['hashes'].extend(hashes)
        for domain in domains:
            #if domain does not match a filename
            if not Pattern.pattern_Filename.match(domain.lower()) and "www" not in domain.lower():
                self.dictValues['domains'].append(domain)
        self.dictValues['keys'].extend(keys)

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
                        self.sort_values(line)  # Extract values from the line
                # Print success message
                print(f"Successfully read values from {self.fname}")
                return self.dictValues
            
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
        # Read values from file
        file_values = self.read_from_file()

        # Combine values and file_values
        combined_values = defaultdict(list)
        for key in values.keys():
            combined_values[key] = values[key] + file_values[key]

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
```

---

#### Data validation Class


```python
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
```

---

#### Utils

### Date Format

```python
def utc2local(utc):
    """
    Convert UTC time to local time.

    Parameters:
    utc (datetime): The UTC time to convert.

    Returns:
    datetime: The local time.
    """
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset

def get_api_key(api_key: str, api_key_file: str) -> str:
    """
    Get the API key.

    Parameters:
    api_key (str): The API key.
    api_key_file (str): The file containing the API key.

    Returns:
    str: The API key.
    """
    # Get the API key
    if api_key:
        return api_key
    elif api_key_file:
        with open(api_key_file, "r") as f:
            return f.read().strip()
    elif os.getenv("VTAPIKEY"):
        return os.getenv("VTAPIKEY")
    else:
        print("No API key provided.")
        exit()

def get_proxy(proxy: str) -> str:
    """
    Get the proxy.

    Parameters:
    proxy(str): The proxy.
    Returns:
    str: The proxy.
    
    """
    if proxy:
        return proxy
    elif os.getenv("VT_PROXY"):
        return os.getenv("VT_PROXY")
    else:
        print("No Proxy provided.")
        return None

```

---

#### Output handler Class

```python
class OutputHandler:
    """
    A class for outputting data to files (CSV / TXT).

    Attributes:
        case_num (str): The case number.
        csvfilescreated (List[str]): A list of CSV files created by the script.
    
    Methods:
        _get_file_path(value_type): Get the file path for a given value type.
        output_to_csv(data, value_type): Output data to a CSV file.
        output_to_txt(data, value_type): Output data to a TXT file.
    
    """
    def __init__(self, case_num: str):
        self.case_num = case_num
        self.csvfilescreated = []

    def _get_file_path(self, value_type: str) -> str:
        """
        Get the file path for a given value type.

        Parameters:
        value_type (str): The type of data to output.

        Returns:
        str: The file path.
        """
        now = datetime.now()  # Get the current time
        case_str = self.case_num.zfill(6)  # Zero-pad the case number to 6 digits
        # Format the date and time as a string
        today = now.strftime("%Y%m%d_%H%M%S")

        # Map value types to file name suffixes
        file_name_suffixes = {
            "IP": "IP_Analysis.csv",
            "HASH": "Hashes_Analysis.csv",
            "URL": "URL_Analysis.csv",
            "DOMAIN": "Domains_Analysis.csv"
        }
        # Get the file name suffix for the value type
        file_name_suffix = file_name_suffixes.get(value_type)

        # Raise an error if the value type is invalid
        if file_name_suffix is None:
            raise ValueError(f"Invalid value type: {value_type}")

        # Create the file path
        file_path = f"Results/{today}#{case_str}_{file_name_suffix}"
        self.csvfilescreated.append(file_path)

        return file_path

    def output_to_csv(self, data: List[Dict[str, str]], value_type: str) -> None:
        """
        Output data to a CSV file.

        Parameters:
        data (List[Dict[str, str]]): The data to output.
        value_type (str): The type of data to output.

        Returns:
        None
        """
        file_path = self._get_file_path(value_type)
        # Write the contents of the table to a file in CSV format
        with open(file_path, 'w', newline='') as data_file:
            # Create the CSV writer object
            csv_writer = csv.DictWriter(
                data_file, fieldnames=data[0][0].keys(), delimiter=';')

            # Write the header row
            csv_writer.writeheader()
            for i in range(len(data)):
                # Write the data rows
                for obj in data[i]:
                    csv_writer.writerow(obj)

        #print(f"\nResults successfully printed in:\n\t{file_path}\n")

    def output_to_txt(self, data: List[List[str]], value_type: str) -> None:
        """
        Output data to a TXT file.

        Parameters:
        data (List[List[str]]): The data to output.
        value_type (str): The type of data to output.

        Returns:
        None
        """
        file_path = self._get_file_path(value_type)

        # Write the contents of the table to a file in TXT format
        with open(file_path.replace("csv", "txt"), "w", encoding="utf-8", newline="") as f:
            f.write(str(data))

        print(f"\nResults successfully printed in:\n\t{file_path}\n\t{file_path.replace('csv', 'txt')}\n")   

```

---

#### Creating table to output

##### Table Class

```python
class PrettyTable:
    """
    A class for creating a table of data.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        self.headers = headers
        self.data = data

    def divide_list(self, lst, n):
        return [lst[i:i + n] for i in range(0, len(lst), n)]

    def create_table(self):
        """
        Create a table of data.

        Returns:
        str: The table as a string.
        """
        # Create the table
        table = PT()
        table.field_names = self.headers
        table.reversesort = True

        # Filter the data to only include rows with the same length as the headers list

        filtered_data = self.divide_list(self.data, len(self.headers))
        # Add the rows to the table
        for row in filtered_data:
            table.add_row(row)

        # Return the table as a string
        return str(table)
```

---

#### Getting the report from VirusTotal

##### VTClient Class

```python
class VirusTotalClient:
    """
    A class for interacting with the VirusTotal API.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.

    Methods:
    initClient(self): Initialize the VirusTotal client.

    """

    def __init__(self, api_key: str, proxy: str = None):
        self.api_key = api_key
        self.proxy = proxy

    def initClient(self):
        # Initialize the VirusTotal client
        client = vt.Client(self.api_key, proxy=self.proxy)

        return client  # Return the client
```

##### VTReporter Class

```python
class VTReporter:
    def __init__(self, vt):
        self.vt = vt
    
    def create_report(self, value_type, value):
        """
        Create a report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.

        Returns:
        dict: The report for the value.
        """
        # Create a report for the value
        if value_type == "IP":
            report = self.vt.get_object(f"/ip_addresses/{value}")
        elif value_type == "DOMAIN":
            report = self.vt.get_object(f"/domains/{value}")
        elif value_type == "URL":
            report = self.vt.get_object(f"/urls/{url_id(value)}")
        elif value_type == "HASH":
            report = self.vt.get_object(f"/files/{value}")

        return report

    def create_object(self, value_type, value, report):
        """
        Create an object for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create an object for.
        report (dict): The report for the value.

        Returns:
        dict: The object for the value.
        """
        # Create an object for the value
        malicious = report.last_analysis_stats["malicious"]
        suspicious = report.last_analysis_stats["suspicious"]
        undetected = report.last_analysis_stats["undetected"]
        harmless = report.last_analysis_stats["harmless"]
        malicious_score = f"{malicious} \\ {malicious + undetected + suspicious + harmless}"
        suspi_score = f"{suspicious} \\ {malicious + undetected + suspicious + harmless}"
        safe_score = f"{harmless} \\ {malicious + undetected + suspicious + harmless}"
        if value_type == "IP":
            object = {
                "IP Address" : value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "owner": getattr(report, 'as_owner', 'No owner found'),
                "location": f"{report.continent} / {report.country}" if hasattr(report, 'continent') and hasattr(report, 'country') else "Not found",
                "network": getattr(report, 'network', 'No network found'),
                "https_certificate": getattr(report, 'last_https_certificate', 'No https certificate found'),
                "info-ip": {
                    "regional_internet_registry": getattr(report, 'regional_internet_registry', 'No regional internet registry found'),
                    "asn": getattr(report, 'asn', 'No asn found'),
                },
                "link": "https://www.virustotal.com/gui/ip-address/" + value
            }
        elif value_type == "DOMAIN":
            object = {
                "Domain" : value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                'creation_date': getattr(report, 'creation_date', 'No creation date found'),
                "reputation": getattr(report, 'reputation', 'No reputation found'),
                "whois": getattr(report, 'whois', 'No whois found'),
                "info": {
                    'last_analysis_results': getattr(report, 'last_analysis_results', 'No analysis results found'),
                    'last_analysis_stats': getattr(report, 'last_analysis_stats', 'No analysis stats found'),
                    'last_dns_records': getattr(report, 'last_dns_records', 'No dns records found'),
                    'last_https_certificate': getattr(report, 'last_https_certificate', 'No https certificate found'),
                    'registrar': getattr(report, 'registrar', 'No registrar found'),
                },
                "link": "https://www.virustotal.com/gui/domain/" + value
            }
        elif value_type == "URL":
            object = {
                "URL": value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "title": getattr(report, 'title', 'No Title Found'),
                "final_Url": getattr(report, 'last_final_url', 'No endpoints'),
                "first_scan": str(utc2local(getattr(report, 'first_submission_date', 'No date Found'))),
                "info": {
                    'metadatas': getattr(report, 'html_meta', 'No metadata Found'),
                    'targeted': getattr(report, 'targeted_brand', 'No target brand Found'),
                    'links': getattr(report, 'outgoing_links', 'No links in url'),
                    'redirection_chain': getattr(report, 'redirection_chain', 'No redirection chain Found'),
                    'trackers': getattr(report, 'trackers', 'No tracker Found'),
                },
                "link": f"https://www.virustotal.com/gui/url/{report.id}"
            }
        elif value_type == "HASH":
            object = {
                "Hash (Sha256)": value,
                "malicious_score": malicious_score,
                "suspicious_score": suspi_score,
                "safe_score": safe_score,
                "extension": getattr(report, 'type_extension', 'No extension found'),
                "Size (Bytes)": getattr(report, 'size', 'No size found'),
                "md5": getattr(report, 'md5', 'No md5 found'),
                "sha1": getattr(report, 'sha1', 'No sha1 found'),
                "ssdeep": getattr(report, 'ssdeep', 'No ssdeep found'),
                "tlsh": getattr(report, 'tlsh', 'No tlsh found'),
                "names": ", ".join(getattr(report, 'names', 'No names found')),
                "Type": report.trid[0]["file_type"] if hasattr(report, 'trid') else "No filetype Found",
                "Type Probability": report.trid[0]["probability"] if hasattr(report, 'trid') else "No type probabilty",
                "link": "https://www.virustotal.com/gui/report/"+ value
            }

        return object

    def get_rows(self, value_type, value, report):
        """
        Get the rows for a value and its report.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the rows for.
        report (dict): The report for the value.

        Returns:
        List[List[str]]: The rows for the value and its report.
        """
        # Get the rows for the value and its report
        object = self.create_object(value_type, value, report)
        try:
            object.pop("info")
        except:
            pass
        rows = [[key, value] for key, value in object.items()]

        standard_rows = [
            ["VirusTotal Total Votes", report.get("total_votes", 0)]
        ]
        rows.extend(standard_rows)

        return rows

    def csv_report(self, value_type, value, report):
        """
        Create a CSV report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.
        report (dict): The report for the value.

        Returns:
        List[Dict[str, str]]: The CSV report for the value.
        """
        # Create a CSV report for the value
        object = self.create_object(value_type, value, report)
        csv_report = [object]

        return csv_report

    def get_report(self, value_type, value):
        """
        Get the report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value.
        """
        # Get the report for the value
        report = self.create_report(value_type, value)
        csv_report = self.csv_report(value_type, value, report)
        rows = self.get_rows(value_type, value, report)

        results = {
            "report": report,
            "csv_report": csv_report,
            "rows": rows
        }

        return results
```

---

#### Main Function

##### Init Class

```python
class Initializator:
    """
    A class for initializing the VirusTotal client.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.
    client (vt.Client): The VirusTotal client.
    reporter (VirusTotalReporter): The VirusTotal reporter.
    validator (DataValidator): The data validator.
    output (OutputHandler): The output handler.

    """
    def __init__(self, api_key: str, proxy: str = None, case_num: str = None):
        self.api_key = api_key
        self.proxy = proxy
        self.client = VirusTotalClient(self.api_key, self.proxy).initClient()
        self.reporter = VTReporter(self.client)
        self.validator = DataValidator()
        self.output = OutputHandler(case_num)
```

For the argument we use the <font color="yellow">argparse</font> library.

This library let us add argument and options to our script.

And then we define our app

```python
def analyze_values(args):
    """
    Analyze values.

    Parameters:
    args (Namespace): The arguments passed to the script.
    """
    load_dotenv()
    api_key = get_api_key(args.api_key, args.api_key_file)
    proxy = get_proxy(args.proxy)
    case_number = str(args.case_id or 0).zfill(6)
    print(f"Begining case : #{case_number} ...\n")

    init = Initializator(api_key, proxy, case_number)
    time1 = datetime.now()

    # Get the values to analyze
    values = ValueReader(args.input_file, args.values).read_values()
    if not values:
        print("No values to analyze.")
        exit()

    # Analyze each value type
    results = {}
    for value_type in ["ips", "domains", "urls", "hashes"]:
        if not values[value_type]:
            print(f"No {value_type} to analyze.\n")
            continue

        print(f"Analyzing {len(values[value_type])} {value_type}...\n")
        value_results = []
        for value in values[value_type]:
            try:
                if value_type == "hashes":
                    value_type_str = init.validator.validate_hash(value)
                else:
                    validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
                    value_type_str = validator_func(value)
                if value_type_str:
                    if value_type_str in ["Private", "Localhost", "Everybody"]:
                        continue
                    else:
                        try:
                            value_results.append(init.reporter.get_report(value_type_str.upper(), value))
                        except Exception as e:
                            print(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
                else:
                    logging.warning(f"Invalid {value_type[:-1]}: {value}\n")
            except Exception as e:
                logging.warning(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")

        # Filter out invalid values
        value_results = [result for result in value_results if result]

        # Output the results
        if value_results:
            # Create the table of results
            header_rows = []
            value_rows = []
            for result in value_results:
                for row in result["rows"]:
                    if row[0] not in header_rows:
                        header_rows.append(row[0])
                    value_rows.append(row[1:])
            table = PrettyTable(header_rows, value_rows)
            strtable = table.create_table()

            total_csv_report = [result["csv_report"] for result in value_results]
            init.output.output_to_csv(total_csv_report, "HASH" if value_type == "hashes" else value_type[:-1].upper())

            # Output the results to a TXT file
            init.output.output_to_txt(strtable, "HASH" if value_type == "hashes" else value_type[:-1].upper())
            print(f"{value_type[:-1].upper()} Analysis ended successfully")
        else:
            print(f"No {value_type} to analyze.\n")

        results[value_type] = value_results

    # Close the VirusTotal client
    init.client.close()
    csvfilescreated = list(set(init.output.csvfilescreated))
    time2 = datetime.now()
    total = time2 - time1
    print(f"Analysis done in {total} !")
    print("Thank you for using VT Tools ! ")
    mispchoice(case_number, csvfilescreated)
    for csvfile in csvfilescreated:
        print(f"CSV file created : {csvfile}")
```

Then we initialise the main function for the app launch.

```python
if __name__ == '__main__':
    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", "-f", type=str, help="Input file containing values to analyze.")
    parser.add_argument("--case_id", "-c", type=str, help="Id for the case to create")
    parser.add_argument("--api_key", "-a", type=str, help="VirusTotal API key, default VTAPIKEY env var.")
    parser.add_argument("--api_key_file", "-af", type=str, help="VirusTotal API key in a file.")
    parser.add_argument("--proxy", "-p", type=str, help="Proxy to use for requests.")
    parser.add_argument("values", type=str, nargs="*", help="The values to analyze. Can be IP addresses, hashes, URLs, or domains.")
    args = parser.parse_args()
    
    analyze_values(args)
```
