<p align="center">
    <img src="logo.png" alt= “VirusTotal_tool_logo” width="250" height="250">
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

## How to use ?

### Installation

To install and run VT3_Tools, you will need to have python 3.9 or more installed on your system.

- Clone the repository:
  - git clone <https://github.com/TheoBhang/Analysis_Tool>
- Install all depedencies with:
  - pip install -r requirements.txt

Then the script should be ready to launch

### Usage

#### Locally

```md
Usage: vt3_tools.py [OPTIONS] VALUES...

  Retrieve VirusTotal analysis information for a set of values (IP/Hash/URL).

Options:
    --input_file TEXT     Input file containing values to analyze.
    --case_id NUMBER      Id for the case to create
    --api_key TEXT        VirusTotal API key, default VTAPIKEY env var.
    --api_key_file TEXT   VirusTotal API key in a file.
```

And run :

```sh
# For any help just launch
python3 .\vt3_tools.py 

# By Default if you don't specify a VT API key the script will search in the environment variables.
python3 .\vt3_tools.py --case_id <Case ID> [INPUT_VALUE]

# For Input based analysis with an API KEY:
python3 .\vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> [INPUT_VALUE]

# For File based analysis:
python3 .\vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> --input_file <Path to file>

# You can also use your api key from a file:
python3 .\vt3_tools.py --api_key_file <Path to APIKEY file> --case_id <Case ID> --input_file <Path to file>
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
docker run -v ${pwd}/Results:/vt/Results/ -v ${pwd}/Files:/vt/files/ --rm --name vt_tools vt3_tools:latest

# If you want to use a .env in your local instance you will have to rebuild the image after modifying the env
# By Default if you don't specify a VT API key the script will search in the environment variables.
docker run \
-v ${pwd}/Results:/vt/Results/ \
-v ${pwd}/Files:/vt/files/ \
--rm --name vt_tools vt3_tools:latest  \ 
--input_file <Container Path to file> \
--case_id <Case ID>

# For Input based analysis
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
--rm --name vt_tools vt3_tools:latest \ 
--api_key <Your VT APIKEY> \ 
[INPUT_VALUE] \ 
--case_id <Case ID>

# For File based analysis
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
--rm --name vt_tools vt3_tools:latest \ 
--api_key <Your VT APIKEY> \ 
--input_file <Container Path to file>  \ 
--case_id <Case ID>

# You can also use your api key from a file for this put the file in your previously created Files folder and use:
docker run \ 
-v ${pwd}/Results:/vt/Results/ \ 
-v ${pwd}/Files:/vt/files/ \ 
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

## Code Explaining

### Library used

```python
# importing the module
import os
import re                           # to use RegEx
import sys                          # to interact with the python interpreter
import time                         # to make the Countdown timer
import click                        # to pass arguments to the script
from prettytable import PrettyTable # to format results in table
from datetime import datetime       # to get today's date and hour
from collections import defaultdict # to create a dictionnary of values
from typing import List             # to make a List object
import csv                          # to interact with csv files 
import vt                           # to interact with VirusTotal API V3
from dotenv import load_dotenv
```

---

### Class

The Patern Class is used to store every pattern in our script.

The pattern correspond to Regular Expressions for IP, SHA 256 Hashes and URL.

```python
class Pattern:
    """Analysis Patterns"""

    # pattern to match all valid IPV4 address formats 
    pattern_IP = re.compile(
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')

    # pattern to match more variations of URLs
    pattern_URL = re.compile(
        r'(?:https?://|www\.)(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b)(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)')

    # pattern to match SHA-256 hashes
    pattern_Hash = re.compile(r'\s([a-fA-F0-9]{64})\s')

    # pattern to match API keys that are alphanumeric and have a length of 32 characters
    pattern_API = re.compile(r'[a-zA-Z\d]{32}$')
```

---

### Reading values

#### Read from User input

```python
def read_from_stdin():
    """
    Read lines from standard input.

    Returns:
        List[str]: The lines read from standard input.
    """
    if sys.stdin.isatty():  # Check if standard input is a terminal
        return []  # If standard input is a terminal, return an empty list
    elif sys.stdin.closed:  # Check if standard input is closed
        # If standard input is closed, raise an error
        raise ValueError("Standard input is closed")
    else:
        # If standard input is open, read lines and return them as a list
        return [line.strip() for line in sys.stdin]
```

#### Read from File

```python
def read_from_file(fname):
    """
    Read values from a file

    Parameters:
    fname (str): the name of the file to read from

    Returns:
    dict: a dictionary with four keys: 'ips', 'urls', 'hashes', and 'keys'. The values
          corresponding to these keys are lists of extracted values from the file.
    """
    file_values = defaultdict(list)  # Initialize empty dictionary

    try:
        if fname is not None:  # Only proceed if there is a file name
            with open(fname, encoding="utf8") as f:  # Open file
                fstring = f.read().splitlines()  # Read file and split into list of lines

                # Iterate through each line in the list
                for line in fstring:
                    # Use regular expressions to extract values
                    # Extract IP addresses
                    ip_match = re.search(Pattern.pattern_IP, line)
                    if ip_match:  # If a match is found
                        # Add the match to the 'ips' list
                        file_values['ips'].append(ip_match.group(0))

                    url_match = re.search(
                        Pattern.pattern_URL, line)  # Extract URLs
                    if url_match:  # If a match is found
                        # Add the match to the 'urls' list
                        file_values['urls'].append(url_match.group(0))

                    hash_match = re.search(
                        Pattern.pattern_Hash, line)  # Extract hashes
                    if hash_match:  # If a match is found
                        # Add the match to the 'hashes' list
                        file_values['hashes'].append(hash_match.group(1))

                    key_match = re.search(
                        Pattern.pattern_API, line)  # Extract keys
                    if key_match:  # If a match is found
                        # Add the match to the 'keys' list
                        file_values['keys'].append(key_match.group(1))

    except IOError as e:  # Catch IOError if there is a problem reading the file
        # Print error message
        print("I/O error({0}): {1}".format(e.errno, e.strerror))

    return file_values  # Return the dictionary of extracted values
```

---

### Data validation

#### Validate IP adresses

```python
def validate_ip(ip):
    """
    Validate an IP address and determine its type.

    Parameters:
    ip (str): The IP address to validate.

    Returns:
    str: The type of the IP address (one of "Private", "Localhost", "Everybody", "Public", or None).
    """
    ip_type = None  # Initialize the type to None

    # Check if the IP address is in the correct format
    if Pattern.pattern_IP.match(ip):
        # Use regular expressions to match private, localhost, and "everybody" IP addresses
        ip_patterns = {
        "Private": r"^(0?10\.|172\.(0?1[6-9]|0?2[0-9]|0?3[0-1])\.|192\.168\.|127\.)\d{1,3}\.\d{1,3}$",
        "Localhost": r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
        "Everybody": r"^0\.0\.0\.0$",
        "Public": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        }
    
        for ip_type, pattern in ip_patterns.items():
            if re.fullmatch(pattern, ip):
                # Validate that each octet is a number between 0 and 255, inclusive
                octets = ip.split(".")
                if all(0 <= int(octet) <= 255 for octet in octets):
                    return ip_type
```

#### Validate Hashes

```python
def validate_hash(h):
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
            hash_type = "SHA-256"  # Set the type to "SHA-256"

    return hash_type  # Return the type of the hash
```

#### Validate Urls

```python
def validate_url(u):
    """
    Validate a URL and determine its type.

    Parameters:
    u (str): The URL to validate.

    Returns:
    str: The type of the URL (one of "Valid" or None).
    """
    url_type = None  # Initialize the type to None

    # Check if the URL is in the correct format
    if Pattern.pattern_URL.match(u):
        url_type = "Valid"  # Set the type to "Valid"

    return url_type  # Return the type
```

---

### Date Format

```python
def utc2local(utc):
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset
```

---

### Printing the analysis result

```python
def print_output_in_file(table, x, case_num, value_type):
    """
    Print a report table to a file, with the file name depending on the data type.

    Parameters:
    table (List[List[str]]): The table to print.
    case_num (str): The case number to include in the file name.
    value_type (str): The type of data in the table (one of "IP", "HASH", or "URL").

    Returns:
    None

    Raises:
    ValueError: If the value type is invalid.
    """
    now = datetime.now()  # Get the current time
    case_str = case_num.zfill(6)  # Zero-pad the case number to 6 digits
    # Format the date and time as a string
    today = now.strftime("%Y%m%d_%H%M%S")

    # Map value types to file name suffixes
    file_name_suffixes = {
        "IP": "IP_Analysis.csv",
        "HASH": "Hashes_Analysis.csv",
        "URL": "URL_Analysis.csv",
    }
    # Get the file name suffix for the value type
    file_name_suffix = file_name_suffixes.get(value_type)

    # Raise an error if the value type is invalid
    if file_name_suffix is None:
        raise ValueError(f"Invalid value type: {value_type}")

    # Create the file path
    file_path = f"Results/{today}#{case_str}_{file_name_suffix}"

    # Open the file and write the table to it
    with open(file_path.replace("csv", "txt"), "w", encoding="utf-8", newline="") as f:
        f.write(str(table))
    print("\nResults successfully printed in : \n\t\\\t" +
            file_path + "\n\t\\\t"+file_path.replace("csv", "txt")+"\n")
    # Write the contents of the dictionary to a file in CSV format
    with open(file_path, 'w', newline='') as data_file:
        # Create the CSV writer object
        csv_writer = csv.DictWriter(
            data_file, fieldnames=x[0].keys(), delimiter=';')

        # Write the header row
        csv_writer.writeheader()

        # Write the data rows
        for obj in x:
            csv_writer.writerow(obj)
```

---

### Adding data to Table and to JSON

#### Adding Ip

```python
def output_ip_reports(ip_values, client, ip_dupes, case_number):
    """Print reports to stdout or save to filename"""
    table = PrettyTable()
    case_id = case_number
    value_type = "IP"
    ip_count = 0
    # Table Params
    table.field_names = ["IP", "Malicious Score", "Suspicious Score", "Safe Score","Owner", "ASN", "From", "Network", "Regional Internet Registry", "Permalink"]
    table.reversesort = True
    x = []
    for i in ip_values:
        if validate_ip(i) in ["Private", "Localhost", "Everybody"]:
            pass
        else:
            try:
                ip = client.get_object("/ip_addresses/" + i)

                ip_value = ip
                if ip_value:
                    ip_count += 1

                owner = ip.as_owner if hasattr(
                    ip, 'as_owner') else "No owner found"
                asn = ip.asn if hasattr(ip, 'asn') else "No ASN found"
                location = f"{ip.continent} / {ip.country}" if hasattr(
                    ip, 'continent') and hasattr(ip, 'country') else "Not found"
                network = ip.network if hasattr(
                    ip, 'network') else "No network linked"
                rir = ip.regional_internet_registry if hasattr(
                    ip, 'regional_internet_registry') else "Not on Regional registry"

                malicious = ip.last_analysis_stats["malicious"]
                suspicious = ip.last_analysis_stats["suspicious"]
                undetected = ip.last_analysis_stats["undetected"]
                harmless = ip.last_analysis_stats["harmless"]
                malicious_score = f"{malicious} \\ {malicious + undetected + suspicious + harmless}"
                suspi_score = f"{suspicious} \\ {malicious + undetected + suspicious + harmless}"
                safe_score = f"{harmless} \\ {malicious + undetected + suspicious + harmless}"
                link = "https://www.virustotal.com/gui/ip-address/" + i
                table.add_row([i, malicious_score, suspi_score,
                              safe_score, owner, asn, location, network, rir, link])

                cert = ip.last_https_certificate if hasattr(
                    ip, 'last_https_certificate') else {}
                cert_issuers = cert.get("issuer", "")
                valid = cert.get("validity", {}).get("not_after", "")
                https_cert_sign = cert.get(
                    "cert_signature", {}).get("signature", "")
                https_cert_alg = cert.get("cert_signature", {}).get(
                    "signature_algorithm", "")
                known_names = cert.get("extensions", {}).get(
                    "subject_alternative_name", "")

                x.append({
                    'ip': i,
                    'malicious_score': malicious_score,
                    'suspicious_score': suspi_score,
                    'safe_score': safe_score,
                    'owner': owner,
                    'location': location,
                    'network': network,
                    'info': {
                        'asn': asn,
                        'regional_internet_registry': rir
                    },
                    'https_certificate': {
                        'CA_issuer': cert_issuers,
                        'CA_validity_end_date': valid,
                        'CA_signature': https_cert_sign,
                        'CA_sign_algo': https_cert_alg,
                        'linked_names': known_names
                    },
                    'link': link
                }
                )
            except:
                pass

    if ip_count == 0:
        print("No ip values were good for Analysis")
    else:
        # We send the values to print the table in a file
        print_output_in_file(table, x, case_id, value_type)
```

#### Adding Hash

```python
def output_hash_reports(hash_values, client, hash_dupes, case_num):
    """Print reports to stdout and write them to a file"""
    table = PrettyTable()
    case_id = case_num
    value_type = "HASH"
    hash_count = 0
    # Table Params
    table.field_names = ["Hash (Sha256)", "Malicious Score", "Suspicious Score", "Safe Score", "Extension","Size (Bytes)", "First_Scan_Date", "md5", "sha1", "ssdeep", "Type", "Type Probability", "Permalink"]
    table.reversesort = True
    x = []
    for h in hash_values:
        try:
            file = client.get_object("/files/"+h)

            hash_value = file.sha256
            if hash_value:
                hash_count += 1
            description = file.antiy_info if hasattr(
                file, 'antiy_info') else "No description Found"
            filetype = file.trid[0]["file_type"] if hasattr(
                file, 'trid') else "No filetype Found"
            type_pb = file.trid[0]["probability"] if hasattr(
                file, 'trid') else "No type probabilty"
            date = utc2local(file.first_submission_date) if hasattr(
                file, 'first_submission_date') else "No date Found"
            filename = file.meaningful_name if hasattr(
                file, 'meaningful_name') else "No name Found"
            size = file.size if hasattr(file, 'size') else "No size Found"
            ext = file.type_extension if hasattr(
                file, 'type_extension') else "No extension Found"
            sha1 = file.sha1 if hasattr(file, 'sha1') else "No sha1 hash Found"
            sha256 = file.sha256 if hasattr(
                file, 'sha256') else "No sha256 hash Found"
            md5 = file.md5 if hasattr(file, 'md5') else "No md5 hash Found"
            ssdeep = file.ssdeep if hasattr(
                file, 'ssdeep') else "No ssdeep Found"

            link = "https://www.virustotal.com/gui/file/"+h

            malicious = file.last_analysis_stats["malicious"]
            suspicious = file.last_analysis_stats["suspicious"]
            undetected = file.last_analysis_stats["undetected"]
            harmless = file.last_analysis_stats["harmless"]
            malicious_score = f"{malicious} \\ {malicious + undetected + suspicious + harmless}"
            suspi_score = f"{suspicious} \\ {malicious + undetected + suspicious + harmless}"
            safe_score = f"{harmless} \\ {malicious + undetected + suspicious + harmless}"

            table.add_row([sha256, malicious_score, suspi_score, safe_score,
                          ext, size, date, md5, sha1, ssdeep, filetype, type_pb, link])
            x.append(
                {
                    'hash': sha256,
                    'malicious_score': malicious_score,
                    'suspicious_score': suspi_score,
                    'safe_score': safe_score,
                    'description': description,
                    'extension': ext,
                    'size': size,
                    'md5': md5,
                    'sha1': sha1,
                    'ssdeep': ssdeep,
                    'info': {
                        'type': filetype,
                        'probability': type_pb,
                        'names': filename,
                        'first_scan': str(date)
                    },
                    'link': link
                }
            )
        except:
            pass
    if hash_count == 0:
        print("No hash values were good for Analysis")
    else:
        # We send the values to print the table in a file
        print_output_in_file(table, x, case_id, value_type)
```

#### Adding Url

```python
def output_url_reports(url_values, client, url_dupes, case_num):
    """Print reports to stdout and write them to a file"""
    table = PrettyTable()
    case_id = case_num
    value_type = "URL"
    url_count = 0
    # Table Params
    table.field_names = ["URL", "Malicious Score", "Suspicious Score", "Safe Score","Title", "Times_submitted", "Last Redirection URL", "First_Scan_Date", "Permalink"]
    table.reversesort = True
    x = []
    for u in url_values:
        try:
            url_id = vt.url_id(u)
            url = client.get_object("/urls/"+url_id)

            url_value = url.url
            if url_value:
                url_count += 1
            meta = url.html_meta if hasattr(
                url, 'html_meta') else "No metadata Found"
            finalUrl = url.last_final_url if hasattr(
                url, 'last_final_url') else "No endpoints"
            links = url.outgoing_links if hasattr(
                url, 'outgoing_links') else "No links in url"
            date = utc2local(url.first_submission_date) if hasattr(
                url, 'first_submission_date') else "No date Found"
            title = url.title if hasattr(url, 'title') else "No Title Found"
            trackers = url.trackers if hasattr(
                url, 'trackers') else "No tracker Found"
            rc = url.redirection_chain if hasattr(
                url, 'redirection_chain') else "No redirection chain Found"
            target = url.targeted_brand if hasattr(
                url, 'targeted_brand') else "No target brand Found"
            number = url.times_submitted if hasattr(
                url, 'times_submitted') else "None"

            link = "https://www.virustotal.com/gui/url/"+url.id

            malicious = url.last_analysis_stats["malicious"]
            suspicious = url.last_analysis_stats["suspicious"]
            undetected = url.last_analysis_stats["undetected"]
            harmless = url.last_analysis_stats["harmless"]
            malicious_score = f"{malicious} \\ {malicious + undetected + suspicious + harmless}"
            suspi_score = f"{suspicious} \\ {malicious + undetected + suspicious + harmless}"
            safe_score = f"{harmless} \\ {malicious + undetected + suspicious + harmless}"

            table.add_row([url_value, malicious_score, suspi_score,
                          safe_score, title, number, finalUrl, date, link])
            x.append(
                {
                    'url': url_value,
                    'malicious_score': malicious_score,
                    'suspicious_score': suspi_score,
                    'safe_score': safe_score,
                    'metadatas': meta,
                    'targeted': target,
                    'info': {
                        'title': title,
                        'final_Url': finalUrl,
                        'links': links,
                        'redirection_chain': rc,
                        'first_scan': str(date)
                    },
                    'trackers': trackers,

                    'link': link
                }
            )
        except:
            pass
    if url_count == 0:
        print("No url values were good for Analysis")
    else:
        # We send the values to print the table in a file
        print_output_in_file(table, x, case_id, value_type)
```

---

### Processing File data

Extract values from files:

```python
def process_file_values(file_values):
    # Create a new list to store the values from the defaultdict
    values_list = []

    # Iterate over the values in the defaultdict and append them to the list
    for value in file_values['ips']:
        values_list.append(value)
    for value in file_values['urls']:
        values_list.append(value)
    for value in file_values['hashes']:
        values_list.append(value)
    for value in file_values['keys']:
        values_list.append(value)

    return values_list
```

---

### Main Function

For the argument we use the <font color="yellow">click</font> library.

This library let us add argument and options to our script.

And then we define our app

```python
@click.command()
@click.argument('values', nargs=-1)
@click.option('--input_file', help='Input file containing values to analyze.')
@click.option('--case_id', help='Id for the case to create.')
@click.option('--api_key', envvar='VTAPIKEY', help='VirusTotal API key, default VTAPIKEY env var.')
@click.option('--api_key_file', help='VirusTotal API key in a file.')
def analyze_values(values: List[str], input_file: str, case_id: int, api_key: str, api_key_file: str) -> None:
    """Retrieve VirusTotal analysis information for a set of values (IP/Hash/URL)."""
    load_dotenv()
    file_values = read_from_file(input_file)
    api_value = read_from_file(api_key_file)
    api_key = os.getenv("VTAPIKEY") or api_key or process_file_values(api_value)
    if not api_key:
        exit()

    client = vt.Client(api_key)

    values = list(values)
    values.extend(process_file_values(file_values))
    values.extend(read_from_stdin())
    ip_values = [v for v in values if Pattern.pattern_IP.match(v)]
    hash_values = [v for v in values if re.match(r'[a-fA-F0-9]{64}', v)]
    url_values = [v for v in values if Pattern.pattern_URL.match(v)]
    ip_dupes = ip_values
    hash_dupes = hash_values
    url_dupes = url_values
    # We filter list of ip to remove all None values
    ip_values = list(filter(None, ip_values))
    # We filter list of ip to remove all duplicates
    ip_values = list(dict.fromkeys(ip_values))
    # We filter list of hash to remove all None values
    hash_values = list(filter(None, hash_values))
    # We filter list of hash to remove all duplicates
    hash_values = list(dict.fromkeys(hash_values))
    # We filter list of url to remove all None values
    url_values = list(filter(None, url_values))
    # We filter list of url to remove all duplicates
    url_values = list(dict.fromkeys(url_values))
    time1 = datetime.now()
    try:
        case_number = case_id
        case_str = case_number.zfill(6)
        print("Begining case : #"+case_str+" ...\n")
    except:
        print("No case Id given, use the --case_id argument \n") 
    
    if ip_values:
        print("Starting IP Analysis...")
        output_ip_reports(ip_values, client, ip_dupes, case_number)
        print("IP Analysis ended successfully")
    else:
        print("No IPs to analyze.")
    if hash_values:
        print("Starting Hash Analysis...")
        output_hash_reports(hash_values, client, hash_dupes, case_number)
        print("Hash Analysis ended successfully")
    else:
        print("No hashes to analyze.")
    if url_values:
        print("Starting URL Analysis...")
        output_url_reports(url_values, client, url_dupes, case_number)
        print("Url Analysis ended successfully")
    else:
        print("No URLs to analyze.")
    time2 = datetime.now()
    total = time2 - time1
    print("Analysis done in "+ str(total) +" !\nThank You for using VT Tools !")
```

Then we initialise the main function for the app launch.

```python
if __name__ == '__main__':
  analyze_values()
```
