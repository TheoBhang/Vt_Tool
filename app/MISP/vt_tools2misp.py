import csv
import logging
import os
import warnings
from typing import List, Dict, Optional

from pymisp import ExpandedPyMISP, MISPEvent
from rich.console import Console
from rich.prompt import Prompt

from app.services.misp_service import MispService

console = Console()


# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_misp_event(misp: ExpandedPyMISP, case_str: str) -> MISPEvent:
    """
    Retrieve an existing MISP event by case string or create a new event if not found.

    Parameters:
        misp (ExpandedPyMISP): The MISP instance.
        case_str (str): The case string used to identify the event.

    Returns:
        MISPEvent: The MISP event associated with the case.
    """
    try:
        # Attempt to get the event by case_str
        event = misp.get_event(case_str)
        console.print(f"[bold green]Successfully fetched MISP event: {case_str}[/bold green]")

    except Exception as e:
        # Log the error and proceed to create a new event
        console.print(f"[bold red]Failed to get MISP event for {case_str}: {e}[/bold red]")
        logging.error(f"Failed to get MISP event for {case_str}: {e}")
        console.print("[bold yellow]Creating a new MISP event...[/bold yellow]")

        # Create a new MISP event
        event = misp.new_event(info="VirusTotal Report")

    # Load and return the event into MISPEvent object
    try:
        misp_event_obj = MISPEvent()
        misp_event_obj.load(event)
        return misp_event_obj
    except Exception as e:
        console.print(f"[bold red]Failed to load MISP event: {e}[/bold red]")
        logging.error(f"Failed to load MISP event: {e}")
        raise RuntimeError(f"Unable to load MISP event for {case_str}") from e


def process_csv_file(csv_file: str) -> list:
    """
    Process data from a CSV file and return the data as a list of dictionaries.

    Parameters:
        csv_file (str): The path to the CSV file.

    Returns:
        list: A list of dictionaries representing the rows in the CSV file.

    Raises:
        FileNotFoundError: If the CSV file is not found.
        csv.Error: If there is an issue with the CSV format.
    """
    data = []

    try:
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=",")
            for row in reader:
                data.append(row)
            console.print(f"[bold green]Successfully processed {len(data)} rows from {csv_file}[/bold green]")
    except FileNotFoundError:
        console.print(f"[bold red]Error: The file '{csv_file}' was not found.[/bold red]")
        logging.error(f"File not found: {csv_file}")
    except csv.Error as e:
        console.print(f"[bold red]CSV Error: {e}[/bold red]")
        logging.error(f"CSV Error: {e}")
    except Exception as e:
        console.print(f"[bold red]Unexpected error: {e}[/bold red]")
        logging.error(f"Unexpected error processing {csv_file}: {e}")

    return data



def load_template(template_file: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Load and process the template file.

    Parameters:
        template_file (str): Path to the CSV template file.

    Returns:
        Dict[str, Dict[str, List[str]]]: Processed template data indexed by 'value'.
    """
    template_object = {}

    try:
        with open(template_file, newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            headers = next(reader, None)  # Read header row

            if not headers:
                console.print(f"[bold red]Error: Template file '{template_file}' is empty.[/bold red]")
                return {}

            if "value" not in headers:
                console.print(f"[bold red]Error: 'value' column missing in template file '{template_file}'.[/bold red]")
                return {}

            value_index = headers.index("value")

            for row_idx, row in enumerate(reader, start=1):
                if len(row) != len(headers):
                    console.print(f"[bold red]Error: Row {row_idx} in '{template_file}' has incorrect column count: {row}[/bold red]")
                    continue

                key = row[value_index]  # Extract the primary key

                for idx, header in enumerate(headers):
                    if header == "value":
                        continue
                    template_object.setdefault(key, {}).setdefault(header, []).append(row[idx])

    except FileNotFoundError:
        console.print(f"[bold red]Error: Template file '{template_file}' not found.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error loading template file '{template_file}': {e}[/bold red]")

    return template_object


def apply_template_data(data: List[Dict[str, str]], template_object: Dict[str, Dict[str, List[str]]], template_key: str) -> None:
    """
    Apply template data to the main dataset.

    Parameters:
        data (List[Dict[str, str]]): List of dictionaries representing rows of CSV data.
        template_object (Dict[str, Dict[str, List[str]]]): Loaded template data.
        template_key (str): The key used to match data with the template.
    """
    for row in data:
        key_value = row.get(template_key)
        if key_value and key_value in template_object:
            for key, values in template_object[key_value].items():
                row[key] = values[0] if len(values) == 1 else values  # Store as single value or list





def process_and_submit_to_misp(misp, case_str, csv_files_created, template_file, template) -> None:
    """
    Process CSV files and submit data to MISP.

    Parameters:
        misp: An instance of the MISP object.
        case_str (str): The case identifier string.
        csv_files_created (List[str]): List of CSV files that were created for submission.
    """
    misp_service = MispService()
    misp_event_obj = get_misp_event(misp, case_str)
    console.print(f"[bold]Using MISP event {misp_event_obj.id} for submission[/bold]")

    if not csv_files_created:
        console.print("[bold red]No CSV files found for processing![/bold red]")
        return

    console.print("[bold]Processing CSV files and submitting data to MISP...[/bold]")

    attribute_type_mapping = {
        "file": {
            "sha256": ("sha256", "sha256", "Payload delivery", False),
            "sha1": ("sha1", "sha1", "Payload delivery", False),
            "md5": ("md5", "md5", "Payload delivery", False),
            "ssdeep": ("ssdeep", "ssdeep", "Payload delivery", False),
            "tlsh": ("tlsh", "tlsh", "Payload delivery", False),
            "size": ("size", "size-in-bytes", "Payload delivery", False),
            "meaningful_name": ("filename", "text", "Payload delivery", False),
        },
        "domain-ip": {
            "domain": ("domain", "domain", "Network activity", False),
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "creation_date": ("creation_date", "datetime", "Network activity", False),
            "reputation": ("reputation", "text", "External analysis", False),
            "whois": ("whois", "text", "External analysis", False),
            "info": ("info", "text", "Other", False),
        },
        "url": {
            "url": ("url", "url", "Network activity", False),
            "domain": ("domain", "domain", "Network activity", False),
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "fragment": ("fragment", "text", "Other", False),
            "resource_path": ("resource_path", "text", "Network activity", False),
            "query_params": ("query_params", "text", "Other", False),
            "query_strings": ("query_strings", "text", "Other", False),
            "tld": ("tld", "text", "Other", False),
            "subdomain": ("subdomain", "text", "Other", False),
            "scheme": ("scheme", "text", "Other", False),
            "title": ("title", "text", "Other", False),
            "final_url": ("final_url", "url", "Network activity", False),
            "first_scan": ("first_scan", "datetime", "Other", False),
            "info": ("info", "text", "Other", False),
        },
        "ip-port": {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "port": ("port", "port", "Network activity", False),
            "protocol": ("protocol", "text", "Network activity", False),
            "owner": ("owner", "text", "Other", False),
            "location": ("country-code", "text", "Network activity", False),
            "network": ("network", "text", "Other", False),
            "https_certificate": ("https_certificate", "text", "External analysis", False),
            "regional_internet_registry": ("regional_internet_registry", "text", "External analysis", False),
            "asn": ("AS", "AS", "Network activity", False),
        },
        "general": {
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
            "link": ("link", "link", "External analysis", False),
        }
    }

    for csv_file in csv_files_created:
        console.print(f"[bold]Processing CSV file: {csv_file}[/bold]")
        try:
            data = process_csv_file(csv_file)
            if not data:
                console.print(f"[bold yellow]No data found in {csv_file}[/bold yellow]")
                continue

            object_type = misp_service.identify_object_type(csv_file)
            console.print(f"[bold green]Detected format: {object_type}[/bold green]")

            attribute_mapping = attribute_type_mapping[object_type].copy()
            attribute_mapping.update(attribute_type_mapping["general"])

            template_object = load_template(template_file) if template_file else {}
            template_key = {"file": "hash", "url": "url", "ip-port": "ip", "domain-ip": "domain"}.get(object_type)

            misp_objects = misp_service.objects_from_csv(
                data, object_type, attribute_mapping,
                template_object=template_object, template_key=template_key,
            )
            submit_misp_objects(misp, misp_event_obj, misp_objects)
        except ValueError as e:
            console.print(f"[bold red]{e}, skipping...[/bold red]")
            continue
        except Exception as e:
            console.print(f"[bold red]Failed to process CSV file '{csv_file}': {e}[/bold red]")
            continue

    console.print("[bold green]All CSV files processed and submitted successfully![/bold green]")


def submit_misp_objects(misp, misp_event, misp_objects) -> None:
    """
    Submit a list of MISP objects to a MISP event.
    """
    if not misp_objects:
        console.print("[bold yellow]No MISP objects to submit.[/bold yellow]")
        return

    console.print(f"[bold]Submitting {len(misp_objects)} MISP objects to event {misp_event.id}...[/bold]")

    for misp_object in misp_objects:
        if not misp_object.attributes:
            console.print(f"[bold yellow]Warning: MISP object '{misp_object.name}' has no attributes.[/bold yellow]")
            continue

        console.print(f"Submitting object: {misp_object.name} with {len(misp_object.attributes)} attributes")

        try:
            misp_object.uuid = None
            for attr in misp_object.attributes:
                attr.uuid = None
            misp.add_object(misp_event.id, misp_object)
            console.print(f"[bold green]Successfully added MISP object {misp_object.name}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to add MISP object {misp_object.name}: {e}[/bold red]")
            logging.error(f"Failed to add MISP object {misp_object.name}: {e}")

    try:
        misp.update_event(misp_event)
        updated_event_dict = misp.get_event(misp_event.id)
        updated_event = MISPEvent()
        updated_event.load(updated_event_dict)

        console.print(f"[bold green]MISP event {misp_event.id} updated successfully with {len(updated_event.Object)} objects.[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Failed to update MISP event: {e}[/bold red]")
        logging.error(f"Failed to update MISP event: {e}")



def misp_event(case_str, csvfilescreated, template_file, template) -> None:
    """
    Initialize MISP connection and start the process of sending data to MISP.

    Parameters:
        case_str: Case identifier or name for which MISP event will be created.
        csvfilescreated: List of created CSV files to be processed and submitted to MISP.
    """
    # Disable warnings from the VirusTotal API and related PyMISP warnings
    warnings.filterwarnings("ignore")
    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
        message="The template .* doesn't have the object_relation .*",
    )

    # Set logging levels to suppress unnecessary output
    logging.getLogger("Python").setLevel(logging.CRITICAL)
    logging.getLogger().setLevel(logging.CRITICAL)

    try:
        # Prompt for MISP key and URL if they are not set as environment variables
        console.print("[bold]Initializing MISP connection...[/bold]")
        misp_key = os.getenv("MISPKEY")
        misp_url = os.getenv("MISPURL")

        if not misp_key:
            misp_key = Prompt.ask("[bold]Enter your MISP key[/bold]")
        if not misp_url:
            misp_url = Prompt.ask("[bold]Enter your MISP URL[/bold]")

        # Establish MISP connection
        misp = ExpandedPyMISP(misp_url, misp_key, False)
        console.print("[bold green]MISP connection established successfully.[/bold green]")

        # Process and submit data to MISP
        process_and_submit_to_misp(misp, case_str, csvfilescreated,template_file, template)

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on Ctrl+C
    except Exception as e:
        console.print(f"[bold red]An error occurred while initializing MISP: {e}[/bold red]")
        console.print("[bold red]Exiting...[/bold red]")


def misp_choice(case_str: str, csvfilescreated: list, template_file: Optional[str] = None, template: Optional[str] = None) -> None:
    """
    Ask the user if they want to send the results to MISP and proceed accordingly.

    Parameters:
        case_str: Case identifier for the MISP event.
        csvfilescreated: List of CSV files to be processed and submitted.
        template_file: Template file used in template mode, if any.
        template: Template structure used in template mode, if any.
    """
    try:
        # Prompt the user for a decision
        console.print("[bold]Do you want to send the results to MISP?[/bold]")
        console.print("- Yes (1, Y, yes)")
        console.print("- No (2, N, no)")

        # Get the user's input
        choice = Prompt.ask("[bold]Enter your choice[/bold]").strip().lower()

        # Handle user choice for Yes
        if choice in ["1", "y", "yes"]:
            if case_str == "000000":
                # If the case ID is '000000', ask for a valid MISP event ID
                case_str = Prompt.ask("[bold]Please enter the MISP event ID[/bold]")

            # Proceed with MISP processing and submission
            misp_event(case_str, csvfilescreated, template_file, template)

        # Handle user choice for No
        elif choice in ["2", "n", "no"]:
            console.print("[bold yellow]MISP event not created.[/bold yellow]")

        # Invalid input handling
        else:
            console.print("[bold red]Invalid choice. Please enter a valid option.[/bold red]")
            misp_choice(case_str, csvfilescreated, template_file, template)  # Recursively prompt until valid input

    except KeyboardInterrupt:
        console.print("[bold red]Exiting...[/bold red]")  # Graceful exit on keyboard interrupt
    except Exception as e:
        console.print(f"[bold red]An error occurred: {e}[/bold red]")  # Catch unexpected errors
        console.print("[bold red]Exiting...[/bold red]")
