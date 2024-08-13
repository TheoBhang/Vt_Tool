<p align="center">
    <img src="assets/VTTools Logo.webp" alt="VirusTotal Tool Logo" width="250" height="250">
</p>

# THA-CERT VirusTotal Analysis Tool Documentation

Welcome to the VirusTotal Analysis Tool by THA-CERT!

This tool retrieves analysis information for a set of values (IP addresses, hashes, URLs, domains) from VirusTotal. It simplifies and speeds up the analysis of files, such as log files, by automatically querying VirusTotal for any relevant data.

## Goals

The primary goal of this tool is to assist in the identification and analysis of IP addresses, hashes, and URLs within files using regular expressions (RegEx). The tool checks whether these objects have been previously submitted to VirusTotal and retrieves their reports. If an object has not been submitted, the tool will not submit it for analysis.

This tool is particularly useful for:

- Investigating files during incident response or threat hunting.
- Quickly identifying suspicious elements in large datasets.
- Simplifying data export to platforms like MISP, StrangeBee's TheHive, or others.

Results are sorted by object category and saved into two files:
1. **TXT File**: A condensed version of the VirusTotal report, highlighting the most relevant findings.
2. **CSV File**: A detailed report that can be converted to JSON for easy integration with other tools.

If desired, the results can also be sent directly to MISP using the script’s options, with Docker integration available by default.

## Installation

### Prerequisites

Ensure you have Python 3.9 or later installed on your system.

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/TheoBhang/Analysis_Tool
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. The script is now ready to run!

## Usage

### Command-Line Interface

The tool can be used in several ways, depending on your needs:

#### Basic Usage

```bash
usage: vt3_tools.py [-h] [--input_file INPUT_FILE] [--case_id CASE_ID] [--api_key API_KEY]
                    [--api_key_file API_KEY_FILE] [--proxy PROXY]
                    [values ...]
```

- **values**: The values to analyze (IP addresses, hashes, URLs, domains).

#### Options

- `-h, --help`: Show this help message and exit.
- `-f, --input_file INPUT_FILE`: Specify the input file containing values to analyze.
- `-c, --case_id CASE_ID`: Specify the case ID (or MISP event UUID) for which to create or update a report.
- `-a, --api_key API_KEY`: Provide the VirusTotal API key (if not set as an environment variable).
- `-af, --api_key_file API_KEY_FILE`: Path to a file containing the VirusTotal API key.
- `-p, --proxy PROXY`: Specify a proxy to use for requests.

### Examples

1. **Display help:**
   ```bash
   python3 vt3_tools.py -h
   ```

2. **Basic Analysis:**
   ```bash
   python3 vt3_tools.py --case_id <Case ID> [INPUT_VALUE]
   ```

3. **Input-based Analysis with API Key:**
   ```bash
   python3 vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> [INPUT_VALUE]
   ```

4. **File-based Analysis:**
   ```bash
   python3 vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> --input_file <Path to file>
   ```

5. **Using API Key from a File:**
   ```bash
   python3 vt3_tools.py --api_key_file <Path to APIKEY file> --case_id <Case ID> --input_file <Path to file>
   ```

6. **Using a Proxy:**
   ```bash
   python3 vt3_tools.py --api_key <Your VT APIKEY> --case_id <Case ID> --input_file <Path to file> --proxy <Proxy URL>
   ```
