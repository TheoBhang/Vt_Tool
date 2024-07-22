<p align="center">
    <img src="assets/logo.png" alt= “VirusTotal_tool_logo” width="250" height="250">
</p>

# THA-CERT VirusTotal Analysis Tool Documentation

Welcome to the VirusTotal analysis tool by THA-CERT !

This script will retrieve analysis information for a set of values (IP/Hash/URL/Domain) from VirusTotal.

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
                        ID for the case to create (Or MISP event UUID to create or update)
  --api_key API_KEY, -a API_KEY
                        VirusTotal API key, default VTAPIKEY env var
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

