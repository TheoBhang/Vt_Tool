''' Convert a VirusTotal report into MISP objects '''
# Revisited view of the https://github.com/MISP/PyMISP/blob/main/examples/vt_to_misp.py script
import csv
from collections import defaultdict
import logging
import warnings
import os
import pymisp
import urllib3
urllib3.disable_warnings()

# Disable warnings from the VirusTotal API
warnings.filterwarnings("ignore")

logging.getLogger("Python").setLevel(logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)

def get_misp_event(misp, case_str):
    '''
    Get or create a MISP event for the given case string

    :param misp: PyMISP API object for interfacing with MISP
    :param case_str: The case string to use in the MISP event title
    '''
    # Search for existing event with the given case string
    if case_str:
        event = misp.get_event(case_str)
    else:
        event = misp.new_event(info="VirusTotal Report")
    misp_event = pymisp.MISPEvent()
    misp_event.load(event)
    return misp_event

def main(misp, case_str, csvfilescreated):
    '''
    Main program logic for submitting data to MISP

    :param misp: PyMISP API object for interfacing with MISP
    :param case_str: The case string to use in the MISP event title
    :param csvfilescreated: A list of CSV files to read data from
    '''
    misp_event = get_misp_event(misp, case_str)
    columns = defaultdict(list) # each value in each column is appended to a list
    print(f"Using MISP event {misp_event.id} for submission")
    for csvfile in csvfilescreated:
        with open(csvfile, newline='') as f:
            csv_reader = csv.reader(f, delimiter=";")
            readrows = csv.DictReader(f)
            counter = 0
            for row in readrows:
                for (k,v) in row.items(): # go over each column name and value 
                    columns[k].append(v)
            for line in csv_reader:
                if not line:
                    continue
                if counter == 0:
                    counter += 1
                    continue
                object_name = None
                attributes = {}

                if "Hash" in csvfile:
                    object_name = "file"
                    attributes = {
                        "sha256": columns["Hash (Sha256)"][counter],
                        "md5": columns["md5"][counter],
                        "size": columns["Size (Bytes)"][counter],
                        "sha1": columns["sha1"][counter],
                        "ssdeep": columns["ssdeep"][counter],
                        "tlsh": columns["tlsh"][counter],
                        "filename": columns["filename"][counter],
                        "vt-score": columns["malicious_score"][counter],
                        "text": columns["Type"][counter],
                        "link": columns["link"][counter]
                    }
                elif "URL" in csvfile:
                    object_name = "url"
                    attributes = {
                        "url": getattr(line, "URL", None),
                        "vt-score": getattr(line, "malicious_score", None),
                        "metadatas": getattr(line, "metadatas", None),
                        "targeted": getattr(line, "targeted", None),
                        "text": getattr(line, "final_Url", None),
                        "trackers": getattr(line, "trackers", None),
                        "link": getattr(line, "link", None)
                    }
                elif "IP" in csvfile:
                    object_name = "domain-ip"
                    attributes = {
                        "ip-src": getattr(line, "IP", None),
                        "vt-score": getattr(line, "malicious_score", None),
                        "owner": getattr(line, "owner", None),
                        "location": getattr(line, "location", None),
                        "network": getattr(line, "network", None),
                        "text": getattr(line, "info_ip", None),
                        "certificate": getattr(line, "https_certificate", None),
                        "link": getattr(line, "link", None)
                    }
                elif "Domain" in csvfile:
                    object_name = "domain"
                    attributes = {
                        "domain": getattr(line, "Domain", None),
                        "vt-score": getattr(line, "malicious_score", None),
                        "creation_date": getattr(line, "creation_date", None),
                        "text": getattr(line, "whois", None),
                        "link": getattr(line, "link", None)
                    }
                if object_name:
                    print(attributes)
                    misp_object = pymisp.MISPObject(name=object_name)
                    print(f"Adding {object_name} to MISP event")
                    if attributes:
                        for attr_name, attr_value in attributes.items():
                            if attr_name == "ip-src":
                                misp_object.add_attribute(attr_name, value=attr_value, type="ip-src")
                            elif attr_name == "url":
                                misp_object.add_attribute(attr_name, value=attr_value, type="url")
                            elif attr_name == "sha256":
                                misp_object.add_attribute(attr_name, value=attr_value, type="sha256")
                            elif attr_name == "md5":
                                misp_object.add_attribute(attr_name, value=attr_value, type="md5")
                            elif attr_name == "sha1":
                                misp_object.add_attribute(attr_name, value=attr_value, type="sha1")
                            elif attr_name == "ssdeep":
                                misp_object.add_attribute(attr_name, value=attr_value, type="ssdeep")
                            elif attr_name == "tlsh":
                                if attr_value != "No tlsh Found":
                                    misp_object.add_attribute(attr_name, value=attr_value, type="tlsh")
                            elif attr_name == "link":
                                misp_object.add_attribute(attr_name, value=attr_value, type="link")
                            elif attr_name == "size":
                                misp_object.add_attribute(attr_name, value=attr_value, type="size-in-bytes")
                            else:
                                misp_object.add_attribute(attr_name, value=attr_value, type="text")

                        try:
                            r = misp.add_object(misp_event, misp_object)
                            submit_to_misp(misp, misp_event, r)
                        except Exception as e:
                            print(f"Failed to submit MISP object: {e}")

def submit_to_misp(misp, misp_event, misp_objects):
    '''
    Submit a list of MISP objects to a MISP event

    :misp: PyMISP API object for interfacing with MISP

    :misp_event: MISPEvent object

    :misp_objects: List of MISPObject objects. Must be a list
    '''
    # Add MISP objects to the event
    for misp_object in misp_objects:
        misp.add_object(misp_event.id, misp_object)
    # Update the event
    try:
        misp.update_event(misp_event)
    except:
        pass
            

def misp_event(case_str, csvfilescreated):
    try:
        print("Initializing MISP connection...")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")
        if not misp_url:
            misp_url = input("Enter your MISP URL: ")
        if not misp_key:
            misp_key = input("Enter your MISP key: ")
        misp = pymisp.ExpandedPyMISP(misp_url, misp_key, False)
        print("MISP connection established successfully.")

        # Start checking VT and converting the reports
        main(misp, case_str, csvfilescreated)


    except KeyboardInterrupt:
        print("Exiting...")
    except pymisp.exceptions.InvalidMISPObject as err:
        logging.error(err)
        
def mispchoice(case_str, csvfilescreated):
    """
    Asks the user if they want to send the results to MISP and calls the misp_event function if the user chooses to do so.

    :param case_str: A string representing the case.
    :param csvfilescreated: A list of CSV files created.
    """
    print("Do you want to send the results to MISP?")
    print("Yes (1, Y, yes)")
    print("No (2, N, no)")
    try:
        choice = input("Enter your choice: ")
    except KeyboardInterrupt:
        print("Exiting...")
        return
    if choice.lower() in ["1", "y", "yes"]:
        misp_event(case_str, csvfilescreated )
    elif choice.lower() in ["2", "n", "no"]:
        print("MISP event not created.")
    else:
        print("Invalid choice. Please try again.")
        mispchoice(case_str, csvfilescreated)
