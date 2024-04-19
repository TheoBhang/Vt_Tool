''' Convert a VirusTotal report into MISP objects '''
# Revisited view of the https://github.com/MISP/PyMISP/blob/main/examples/vt_to_misp.py script
import csv
import os
import logging
import warnings
import pymisp

# Disable warnings
warnings.filterwarnings("ignore")

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_misp_event(misp, case_str):
    """
    Get or create a MISP event for the given case string.

    :param misp: PyMISP API object for interfacing with MISP.
    :param case_str: The case string to use in the MISP event title.
    :return: The MISP event object.
    """
    try:
        if case_str:
            event = misp.get_event(case_str)
        else:
            event = misp.new_event(info="VirusTotal Report")
        misp_event = pymisp.MISPEvent()
        misp_event.load(event)
        return misp_event
    except Exception as e:
        logger.error(f"Failed to get or create MISP event: {e}")

def process_csv_file(csv_file):
    """
    Process data from a CSV file.

    :param csv_file: Path to the CSV file.
    :return: A list of dictionaries containing row data.
    """
    data = []
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            try:
                data.append(row)
            except Exception as e:
                logger.error(f"Failed to process row: {e}")
    return data

def create_misp_objects_from_csv(data, object_name):
    """
    Create MISP objects from CSV data.

    :param data: List of dictionaries containing row data.
    :param object_name: Name of the MISP object.
    :return: List of MISP objects.
    """
    misp_objects = []
    for row in data:
        try:
            misp_object = pymisp.MISPObject(name=object_name)
            for key, value in row.items():
                try:
                    attribute_type = get_misp_attribute_type(key)
                    if attribute_type:
                        misp_object.add_attribute(key, value=value, type=attribute_type)
                except Exception as e:
                    logger.error(f"Failed to add attribute to MISP object: {e}")
            misp_objects.append(misp_object)
        except Exception as e:
            logger.error(f"Failed to create MISP object: {e}")
            logger.info("Skipping to the next row...")
    return misp_objects

def get_misp_object_name(csv_file):
    """
    Get the MISP object name based on the CSV file name.

    :param csv_file: Path to the CSV file.
    :return: MISP object name.
    """
    if "Hash" in csv_file:
        return "file"
    elif "URL" in csv_file:
        return "url"
    elif "IP" in csv_file:
        return "ip"
    elif "Domain" in csv_file:
        return "domain"
    else:
        return "unknown"  # Handle other cases accordingly

def get_misp_attribute_type(attr_name):
    """
    Get MISP attribute type based on attribute name.

    :param attr_name: Name of the attribute.
    :return: MISP attribute type or None if not found.
    """
    attribute_types = {
        "ip-src": "ip-src",
        "url": "url",
        "sha256": "sha256",
        "md5": "md5",
        "sha1": "sha1",
        "ssdeep": "ssdeep",
        "tlsh": "tlsh",
        "link": "link",
        "size": "size-in-bytes"
    }
    return attribute_types.get(attr_name)

def process_and_submit_to_misp(misp, case_str, csv_files_created):
    """
    Process CSV files and submit data to MISP.

    :param misp: PyMISP API object for interfacing with MISP.
    :param case_str: The case string to use in the MISP event title.
    :param csv_files_created: A list of CSV files to read data from.
    """
    misp_event = get_misp_event(misp, case_str)
    print(f"Using MISP event {misp_event.id} for submission")
    for csv_file in csv_files_created:
        try:
            object_name = get_misp_object_name(csv_file)
            data = process_csv_file(csv_file)
            for _ in range(len(data)):
                misp_objects = create_misp_objects_from_csv(data, object_name)
                try:
                    misp.add_objects(misp_event, misp_objects)
                    misp.update_event(misp_event)
                except Exception as e:
                    print(f"Failed to submit MISP objects: {e}")
        except Exception as e:
            print(f"Failed to process CSV file: {e}")

def submit_misp_objects(misp, misp_event, misp_objects):
    """
    Submit a list of MISP objects to a MISP event.

    :param misp: PyMISP API object for interfacing with MISP.
    :param misp_event: MISPEvent object.
    :param misp_objects: List of MISPObject objects.
    """
    try:
        # Add MISP objects to the event
        for misp_object in misp_objects:
            try:
                misp.add_object(misp_event.id, misp_object)
            except Exception as e:
                logging.error(f"Failed to add MISP object: {e}")
        # Update the event
        misp.update_event(misp_event)

        logging.info("MISP objects submitted successfully.")

    except Exception as e:
        logging.error(f"Failed to submit MISP objects: {e}")
        

def misp_event(case_str, csvfilescreated):
    """
    Initialize MISP connection and start the process of sending data to MISP.

    :param case_str: A string representing the case.
    :param csvfilescreated: A list of CSV files created.
    """
    try:
        logger.info("Initializing MISP connection...")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")

        if not misp_key:
            misp_key = input("Enter your MISP key: ")
        if not misp_url:
            misp_url = input("Enter your MISP URL: ")

        misp = pymisp.ExpandedPyMISP(misp_url, misp_key, False)
        logger.info("MISP connection established successfully.")

        # Start the process
        process_and_submit_to_misp(misp, case_str, csvfilescreated)

    except KeyboardInterrupt:
        logger.info("Exiting...")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        logger.info("Exiting...")
        
def misp_choice(case_str, csvfilescreated):
    """
    Ask the user if they want to send the results to MISP and proceed accordingly.

    :param case_str: A string representing the case.
    :param csvfilescreated: A list of CSV files created.
    """
    try:
        print("Do you want to send the results to MISP?")
        print("Yes (1, Y, yes)")
        print("No (2, N, no)")
        choice = input("Enter your choice: ").lower()
        if case_str == "000000":
            case_str = input("Please enter the MISP event ID: ")
        if choice in ["1", "y", "yes"]:
            misp_event(case_str, csvfilescreated)
        elif choice in ["2", "n", "no"]:
            print("MISP event not created.")
        else:
            print("Invalid choice. Please try again.")
            misp_choice(case_str, csvfilescreated)

    except KeyboardInterrupt:
        logger.info("Exiting...")
