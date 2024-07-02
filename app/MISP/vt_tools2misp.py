import csv
import os
import logging
import warnings
import re
from pymisp import ExpandedPyMISP, MISPObject, MISPEvent


def get_misp_event(misp, case_str):
    """
    Get or create a MISP event for the given case string.
    """
    try:
        event = misp.get_event(case_str)
    except Exception as e:
        print(f"Failed to get MISP event: {e}")
        print("Creating a new MISP event...")
        event = misp.new_event(info="VirusTotal Report")
    misp_event = MISPEvent()
    misp_event.load(event)
    return misp_event

def process_csv_file(csv_file):
    """
    Process data from a CSV file.
    """
    data = []
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f, delimiter=",")
        for row in reader:
            try:
                data.append(row)
            except Exception as e:
                print(f"Failed to process row: {e}")
    return data

def get_attribute_mapping(headers, attribute_type_mapping):
    """
    Get the attribute mapping based on CSV headers.
    """
    attribute_mapping = {}
    for header in headers:
        if header in attribute_type_mapping:
            attribute_mapping[header] = attribute_type_mapping[header]
    return attribute_mapping

def create_misp_objects_from_csv(data, object_name, attribute_mapping):
    """
    Create MISP objects from CSV data.
    """
    misp_objects = []
    for row in data:
        try:
            misp_object = MISPObject(name=object_name)
            for key, value in row.items():
                try:
                    if key in attribute_mapping:
                        attr_details = attribute_mapping[key]
                        misp_object.add_attribute(attr_details[0], value=value, type=attr_details[1], category=attr_details[2], to_ids=attr_details[3])
                except Exception as e:
                    print(f"Failed to add attribute {key} to MISP object: {e}")
            misp_objects.append(misp_object)
        except Exception as e:
            print(f"Failed to create MISP object: {e}")
    return misp_objects

def get_misp_object_name(csv_file):
    """
    Get the MISP object name based on the CSV file name.
    """
    if re.search(r'Hash', csv_file, re.IGNORECASE):
        return "file"
    elif re.search(r'URL', csv_file, re.IGNORECASE):
        return "url"
    elif re.search(r'IP', csv_file, re.IGNORECASE):
        return "domain-ip"
    elif re.search(r'Domain', csv_file, re.IGNORECASE):
        return "domain"
    else:
        return "unknown"

def process_and_submit_to_misp(misp, case_str, csv_files_created):
    """
    Process CSV files and submit data to MISP.
    """
    misp_event = get_misp_event(misp, case_str)
    print(f"Using MISP event {misp_event.id} for submission")
    print("Processing CSV files and submitting data to MISP...")
    print('csv_files_created:', csv_files_created)

    attribute_type_mapping = {
        'ip': ('ip-src', 'ip-src', 'Network activity', False, ['tlp:green']),
        'malicious_score': ('malicious_score', 'text', 'Antivirus detection', False, ['tlp:white']),
        'suspicious_score': ('suspicious_score', 'text', 'Antivirus detection', False, ['tlp:white']),
        'safe_score': ('safe_score', 'text', 'Antivirus detection', False, ['tlp:white']),
        'undetected_score': ('undetected_score', 'text', 'Antivirus detection', False, ['tlp:white']),
        'owner': ('owner', 'text', 'Other', False, ['tlp:white']),
        'location': ('location', 'text', 'Other', False, ['tlp:white']),
        'network': ('network', 'text', 'Other', False, ['tlp:white']),
        'https_certificate': ('https_certificate', 'text', 'Other', False, ['tlp:white']),
        'info-ip': ('info-ip', 'text', 'Other', False, ['tlp:white']),
        'link': ('link', 'link', 'External analysis', False, ['tlp:white']),
        'url': ('url', 'url', 'Network activity', False, ['tlp:green']),
        'title': ('title', 'text', 'Other', False, ['tlp:white']),
        'final_Url': ('final_Url', 'link', 'Other', False, ['tlp:white']),
        'first_scan': ('first_scan', 'datetime', 'Other', False, ['tlp:white']),
        'info': ('info', 'text', 'Other', False, ['tlp:white']),
        'sha256': ('sha256', 'sha256', 'Payload delivery', False, ['tlp:green']),
        'md5': ('md5', 'md5', 'Payload delivery', False, ['tlp:white']),
        'sha1': ('sha1', 'sha1', 'Payload delivery', False, ['tlp:white']),
        'ssdeep': ('ssdeep', 'ssdeep', 'Payload delivery', False, ['tlp:white']),
        'size': ('size', 'size-in-bytes', 'Payload delivery', False, ['tlp:white'])
    }

    for csv_file in csv_files_created:
        print(f"Processing CSV file: {csv_file}")
        try:
            data = process_csv_file(csv_file)
            headers = data[0].keys()
            attribute_mapping = get_attribute_mapping(headers, attribute_type_mapping)
            object_name = get_misp_object_name(csv_file)
            misp_objects = create_misp_objects_from_csv(data, object_name, attribute_mapping)
            submit_misp_objects(misp, misp_event, misp_objects)
        except Exception as e:
            print(f"Failed to process CSV file: {e}")

def submit_misp_objects(misp, misp_event, misp_objects):
    """
    Submit a list of MISP objects to a MISP event.
    """
    try:
        for misp_object in misp_objects:
            try:
                misp.add_object(misp_event.id, misp_object)
            except Exception as e:
                print(f"Failed to add MISP object: {e}")
        misp.update_event(misp_event)
        print("MISP objects submitted successfully.")
    except Exception as e:
        print(f"Failed to submit MISP objects: {e}")

def misp_event(case_str, csvfilescreated):
    """
    Initialize MISP connection and start the process of sending data to MISP.
    """
    # Disable warnings from the VirusTotal API
    warnings.filterwarnings("ignore")

    logging.getLogger("Python").setLevel(logging.CRITICAL)
    logging.getLogger().setLevel(logging.CRITICAL)
    # Suppress specific PyMISP warnings related to object templates
    warnings.filterwarnings("ignore", category=UserWarning, message="The template .* doesn't have the object_relation .*")

    try:
        print("Initializing MISP connection...")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")

        if not misp_key:
            misp_key = input("Enter your MISP key: ")
        if not misp_url:
            misp_url = input("Enter your MISP URL: ")

        misp = ExpandedPyMISP(misp_url, misp_key, False)
        print("MISP connection established successfully.")
        process_and_submit_to_misp(misp, case_str, csvfilescreated)
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Exiting...")

def misp_choice(case_str, csvfilescreated):
    """
    Ask the user if they want to send the results to MISP and proceed accordingly.
    """
    try:
        print("Do you want to send the results to MISP?")
        print("Yes (1, Y, yes)")
        print("No (2, N, no)")
        choice = input("Enter your choice: ").lower()
        if choice in ["1", "y", "yes"]:
            if case_str == "000000":
                case_str = input("Please enter the MISP event ID: ")
            misp_event(case_str, csvfilescreated)
        elif choice in ["2", "n", "no"]:
            print("MISP event not created.")
        else:
            print("Invalid choice. Please try again.")
            misp_choice(case_str, csvfilescreated)
    except KeyboardInterrupt:
        print("Exiting...")