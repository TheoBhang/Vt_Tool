import argparse
import sys
import logging
from datetime import datetime
from typing import Dict, List, Tuple

import requests
from requests.exceptions import RequestException

from dotenv import load_dotenv

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.table import Table

from app.DataHandler.utils import get_api_key, get_proxy, get_user_choice
from app.FileHandler.create_table import CustomPrettyTable as cpt
from app.FileHandler.read_file import ValueReader
from app.MISP.vt_tools2misp import misp_choice
from init import Initializator

console = Console()

# TODO Add more templates

TEMPLATE_OPTIONS = {
    "1": "value,comment",
    "2": "value,comment,source",
    "3": "value,category,type,comment,to_ids,tag1,tag2",
}

# validate_value()'s returned type strings that we don't fetch/query for -
# private/reserved IP ranges and hash types VirusTotal doesn't accept.
UNSUPPORTED_VALUE_TYPES = {
    "Private IPv4",
    "Loopback IPv4",
    "Unspecified IPv4",
    "Link-local IPv4",
    "Reserved IPv4",
    "SHA-224",
    "SHA-384",
    "SHA-512",
    "SSDEEP",
}


def setup_logging() -> None:
    """Setup logging configuration."""
    try:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
    except Exception as e:
        console.print(f"[bold red]Error setting up logging: {e}[/bold red]")


def print_welcome_message() -> None:
    """Print the welcome message with ASCII art and title."""
    print_ascii_art()
    print_title()
    print_subtitle()
    print_welcome_panel()


def print_ascii_art() -> None:
    """Prints ASCII art with rich styling."""
    ascii_art = Text(
        r"""
       ^77777!~:.                 :~7?JJJJ?!.     
       :!JYJJJJJ?!:            .~?JJJJJYJ?!^.     
         .!JYJJJJYJ!.         .!!7?JJJJ~:         
.~:        .!JJJJJJY7         77  ~JJJ~           
~YJ7:      :7JJJYJJJY~        7?!!?7!J7.        :^
7JJJJ7:  ^7JJJ7:~?JJY!        :JYY??JYY?^.  .^!?JJ
^JJYJ7:^?JJJ7:~?~:?JJ^       ^?JJJ!^^~~JY?7?JJYJY?
 !J!:^?JJJ!:!?~:?JJJJ?~.  .^?JJJJJJ! ~??J:.~JJJY?:
  .:?YYJJJJ?~^JJJJJJJJY?~.^JYJJJJJJJ?JJ?J!~~JJ7^  
   .^!?JJJYYYJJJJJJJJJ7:7J!:~?YJJJYJ7::^~~~~:.    
       .:^^^^:^7JJJJJJ: 7YYJ!:^?JJ!:              

                :7JYJ~ :!~~~!J!:^.                
                .^:!J!!^:~~~!?JJ7:                
              :7JJ?^:!J^:~JYY~.~?Y7^              

            :7JYJJJY?~:~?JJJJ~ ..:7J?^            
     .::^^^7JJJJJJJJJY?:.~JJ^.~??^!JJJ?^          
  .~?JYYYJJYJJJJJJJJJ7^   .^7~.^JJYJJJJJ?~.       
 ~JJ7!!!^. !YYJJJJJ7:       .^7~:^7?JJJJJY?~.     
!YJJ.       ^~7JJ7:            ^7~.7J?JJJJJYJ!.   
JJJ!          ^JY~               ^~7^~JJJJJJJJJ!. 
JY7.         ~YJY^                 :!JYJJJ^...~JJ^
^JJJ7^    .  !YY7                    :7JY?     ?Y7
 :7JYY!:~????J?~                       :!J?~~!7J?.
   :~7JJYJJ?7^.                          .~7?7!^     
    """,
        justify="center",
        style="cyan",
    )
    console.print(ascii_art)


def print_title() -> None:
    """Prints the main title."""
    title = Text(
        r"""
  _      __      __                        __          _   __ __    ______            __   
 | | /| / /___  / /____ ___   __ _  ___   / /_ ___    | | / // /_  /_  __/___  ___   / /___
 | |/ |/ // -_)/ // __// _ \ /  ' \/ -_) / __// _ \   | |/ // __/   / /  / _ \/ _ \ / /(_-<
 |__/|__/ \__//_/ \__/ \___//_/_/_/\__/  \__/ \___/   |___/ \__/   /_/   \___/\___//_//___/
 """,
        justify="center",
        style="bold yellow",
    )
    console.print(title)


def print_subtitle() -> None:
    """Prints the subtitle."""
    subtitle = Text(
        r"""
  _           _____ _  _   _       ___ ___ ___ _____  
 | |__ _  _  |_   _| || | /_\ ___ / __| __| _ \_   _| 
 | '_ \ || |   | | | __ |/ _ \___| (__| _||   / | |   
 |_.__/\_, |   |_| |_||_/_/ \_\   \___|___|_|_\ |_|   
       |__/                                          
 """,
        justify="center",
        style="bold green",
    )
    console.print(subtitle)


def print_welcome_panel() -> None:
    """Prints the welcome message panel."""
    welcome_message = """
Welcome to the VirusTotal analysis tool by THA-CERT!

This script will retrieve analysis information for a set of values (IP/Hash/URL/Domains) from VirusTotal. 
To use the tool, provide your VirusTotal API key and the values you want to analyze. 
The tool supports input from various sources, including files, standard input, and command line arguments.

Usage: vt3_tools.py [OPTIONS] VALUES...

Retrieve VirusTotal analysis information for a set of values (IP/Hash/URL/Domains).
"""
    console.print(
        Panel(
            Markdown(welcome_message),
            title="[bold green]Welcome![/bold green]",
            border_style="green",
        )
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments with enhanced user feedback."""

    parser = argparse.ArgumentParser(
        description="VT Tools by THA-CERT. This tool retrieves analysis information for a set of values (IP/Hash/URL/Domains) from VirusTotal."
    )

    # Add template file argument
    parser.add_argument(
        "--template_file",
        "-tf",
        type=str,
        help="Template file to use for the analysis. If not provided, the default template will be used.",
    )

    # Add input file argument
    parser.add_argument(
        "--input_file",
        "-f",
        type=str,
        help="Input file containing values to analyze. Supports IP addresses, hashes, URLs, or domains.",
    )

    # Add output directory argument
    parser.add_argument(
        "--output_dir",
        "-o",
        type=str,
        help="Directory to save output files. If not provided, the current directory will be used.",
    )

    # Add type argument
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        choices=["ips", "hashes", "urls", "domains", "all"],
        default="all",
        help="Type of values to analyze: ips, hashes, urls, domains, or all. Default is all.",
    )

    # Add non interactive argument
    parser.add_argument(
        "--non_interactive",
        "-n",
        action="store_true",
        help="Run the script in non-interactive mode. Default is interactive mode.",
    )

    # Add case ID argument
    parser.add_argument(
        "--case_id",
        "-c",
        type=str,
        help="ID for the case to create (Or MISP event UUID to create or update).",
    )

    # Add API key argument
    parser.add_argument(
        "--api_key",
        "-a",
        type=str,
        help="VirusTotal API key. If not provided, the VTAPIKEY environment variable will be used.",
    )

    # Add API key file argument
    parser.add_argument(
        "--api_key_file",
        "-af",
        type=str,
        help="Path to a file containing your VirusTotal API key.",
    )

    # Add proxy argument
    parser.add_argument(
        "--proxy",
        "-p",
        type=str,
        help="Proxy to use for requests. If not provided, no proxy is used.",
    )

    # Add values argument
    parser.add_argument(
        "values",
        type=str,
        nargs="*",
        help="The values to analyze. Can be IP addresses, hashes, URLs, or domains.",
    )

    # Parse the arguments
    args = parser.parse_args()

    # Additional validation and messages
    if not args.api_key and not args.api_key_file:
        console.print(
            "[bold red]Warning! No API key provided. Using environment variable if available.[/bold red]"
        )

    if args.api_key and args.api_key_file:
        console.print(
            "[bold red]Error: You cannot provide both API key and API key file.[/bold red]"
        )
        parser.print_help()
        sys.exit(1)

    if not args.values and not args.input_file and not args.template_file:
        console.print(
            "[bold red]Error: You must provide either a list of values or an input file.[/bold red]"
        )
        parser.print_help()
        sys.exit(1)

    return args


def get_remaining_quota(api_key: str, proxy: str = None, args: argparse.Namespace = None) -> int:
    """Returns the number of hashes that could be queried within this run."""

    url = f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas"
    headers = {"Accept": "application/json", "x-apikey": api_key}

    # Use a session for reusability and performance
    with requests.Session() as session:
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        try:
            response = session.get(url, headers=headers)
            response.raise_for_status()  # Will raise an exception for HTTP error codes
        except RequestException as e:
            logging.error(f"Error retrieving VT Quota: {e}")
            if args and not args.non_interactive:
                console.print(f"[bold red]Error retrieving VT Quota: {e}[/bold red]")
            return 0

        # Parse the response if successful
        if response.status_code == 200:
            json_response = response.json()
            allowed_hourly_queries = json_response["data"]["api_requests_hourly"][
                "user"
            ]["allowed"]
            used_hourly_queries = json_response["data"]["api_requests_hourly"]["user"][
                "used"
            ]
            remaining_quota = allowed_hourly_queries - used_hourly_queries

            return remaining_quota
        else:
            # Log and console print on error response
            logging.error(
                f"Failed to retrieve quota data (HTTP Status code: {response.status_code})"
            )
            if args and not args.non_interactive:
                console.print(
                    f"[bold red]Failed to retrieve quota data (HTTP Status code: {response.status_code})[/bold red]"
                )
            return 0


def count_iocs(ioc_dict: Dict[str, List]) -> int:
    """
    Count the total number of IOCs in the given dictionary.

    Parameters:
    ioc_dict (dict): A dictionary where keys are IOC categories (e.g., IPs, Domains) and values are lists of IOCs.

    Returns:
    int: The total number of IOCs.
    """
    if not isinstance(ioc_dict, dict):
        raise TypeError("Expected a dictionary")

    return sum(len(value) for value in ioc_dict.values() if isinstance(value, list))


def analyze_values(args: argparse.Namespace, value_types: List[str]) -> None:
    """
    Analyze the values provided by the user through the command-line arguments.

    Parameters:
    args (argparse.Namespace): Command-line arguments.
    value_types (list): List of value types (e.g., "ips", "domains", "urls", "hashes").

    Returns:
    None
    """
    # Load environment variables
    load_dotenv()

    # Initialize necessary parameters
    api_key = get_api_key(args.api_key, args.api_key_file)
    proxy = get_proxy(args.proxy)
    case_id = str(args.case_id or 0).zfill(6)

    init = Initializator(api_key, proxy, case_id)
    database = "vttools.sqlite"
    quota_saved = 0
    error_values = 0

    # Establish DB connection
    with init.db_handler.create_connection(database) as conn:
        if conn is None:
            logging.error("Database connection failed.")
            return

        init.db_handler.create_schema(conn)

        # Start the analysis
        start_time = datetime.now()
        if not args.non_interactive:
            console.print("\n[bold blue]Checking for remaining queries...[/bold blue]")
        else:
            logging.info("Checking for remaining queries...")

        remaining_queries = get_remaining_quota(init.api_key, init.proxy,args)
        if remaining_queries == 0:
            if not args.non_interactive:
                console.print(
                    "[bold yellow]No queries remaining for this hour.[/bold yellow]"
                )
                console.print("[bold blue]Check your API key before analysis.[/bold blue]")
                return
            else:
                logging.error("No queries remaining for this hour.")
                logging.warning("Check your API key before analysis.")
                return
        if not args.non_interactive:
            console.print(f"Remaining queries for this hour: {remaining_queries}")
        else:
            logging.info(f"Remaining queries for this hour: {remaining_queries}")

        # Retrieve values to analyze
        if args.template_file:
            table = Table(title="Template Types", title_style="bold yellow")
            table.add_column("Key", justify="center", style="cyan", no_wrap=True)
            table.add_column("Type", justify="center", style="magenta")

            for key, value in TEMPLATE_OPTIONS.items():
                table.add_row(key, value)

            console.print(table)

            choice = Prompt.ask(
                "[bold green]Select an option[/bold green]",
                choices=TEMPLATE_OPTIONS.keys(),
                default="1",
            )
            values = ValueReader(args.template_file, args.values).read_template_values(
                TEMPLATE_OPTIONS[choice]
            )
        else:
            values = ValueReader(args.input_file, args.values).read_values()
        if not values:
            if not args.non_interactive:
                console.print("[bold yellow]No values to analyze.[/bold yellow]")
            else:
                logging.warning("No values to analyze.")
            return
        if not args.non_interactive:
            console.print(
                f"[bold blue]This analysis will use {count_iocs(values)} out of your {remaining_queries} hourly quota.[/bold blue]\n"
            )
        else:
            logging.info(
                f"This analysis will use {count_iocs(values)} out of your {remaining_queries} hourly quota."
            )

        if remaining_queries < count_iocs(values):
            if not args.non_interactive:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] You have {remaining_queries} queries left for this hour, but you are trying to analyze {len(values)} values."
                )
                console.print(
                    "[bold yellow]Some values may be skipped to avoid exceeding the quota.[/bold yellow]\n"
                )
            else:
                logging.warning(
                    f"Warning: You have {remaining_queries} queries left for this hour, but you are trying to analyze {len(values)} values."
                )
                logging.warning("Some values may be skipped to avoid exceeding the quota.")

        # Start the analysis process for each value type
        for value_type in value_types:
            if not values.get(value_type):
                if not args.non_interactive:
                    console.print(
                        f"[bold yellow]No {value_type[:-1].upper()} values to analyze.[/bold yellow]"
                    )
                else:
                    logging.info(f"No {value_type[:-1].upper()} values to analyze.")
                continue
            if not args.non_interactive:
                console.print(
                    Panel(
                        Markdown("## Analysis Started"),
                        title=f"[bold green]{value_type[:-1].upper()} Analysis[/bold green]",
                        border_style="green",
                    )
                )
            else:
                logging.info(f"Starting {value_type[:-1].upper()} analysis...")

            results, skipped_values, error_values = analyze_value_type(
                init, value_type, values[value_type], remaining_queries, conn
            )
            quota_saved += skipped_values

            if results:
                process_results(init, results, value_type)

        # Post-analysis report
        csv_files_created = list(set(init.output.csvfilescreated))
        quota_final = get_remaining_quota(init.api_key, init.proxy,args)
        if not args.non_interactive:
            if quota_saved == 0:
                console.print(
                    "[bold green]Analysis completed. No values were skipped.[/bold green]"
                )
            else:
                console.print(
                    f"[bold green]Analysis completed. {quota_saved} values were skipped as they already exist in the database.[/bold green]"
                )

            console.print(
                f"[bold blue]Errors occurred for {error_values} values.[/bold blue]"
            )
            console.print(
                f"[bold yellow]Remaining queries for this hour: {quota_final}[/bold yellow]"
            )
        else:
            if quota_saved == 0:
                logging.info("Analysis completed. No values were skipped.")
            else:
                logging.info(
                    f"Analysis completed. {quota_saved} values were skipped as they already exist in the database."
                )

            logging.info(f"Errors occurred for {error_values} values.")
            logging.info(f"Remaining queries for this hour: {quota_final}")

        total_time = datetime.now() - start_time
        if not args.non_interactive:
            console.print(f"[bold blue]Total time taken: {total_time}[/bold blue]")
        else:
            logging.info(f"Total time taken: {total_time}")

        # MISP-related action
        if args.template_file:
            misp_choice(
                case_str=case_id,
                csvfilescreated=csv_files_created,
                template_file=args.template_file,
                template=TEMPLATE_OPTIONS[choice],
            )
        else:
            if args.non_interactive:
                console.print(
                    "[bold blue]Non-interactive mode: Skipping MISP integration step.[/bold blue]"
                )
            else:
                misp_choice(case_str=case_id, csvfilescreated=csv_files_created)

        console.print("[bold green]Thank you for using VT Tools! 👍[/bold green]")

        # Close resources
        close_resources(init)


def analyze_value_type(
    init: Initializator, value_type: str, values: List[str], remaining_queries, conn
) -> tuple:
    """Analyze values of a specific type (e.g., hashes, URLs, domains)."""
    results = []
    skipped_values = 0
    error_values = 0

    for value in values:
        if remaining_queries == 0:
            console.print(
                "[bold yellow]No queries remaining for this hour.[/bold yellow]"
            )
            break
        else:
            try:
                result, skipped, errors = analyze_single_value(
                    init, value_type, value, conn
                )
                results.extend(result)
                skipped_values += skipped
                error_values += errors

            except Exception as e:
                logging.error(f"Error analyzing value {value}: {e}")
                error_values += 1

    return results, skipped_values, error_values


def analyze_single_value(
    init: Initializator, value_type: str, value: str, conn
) -> tuple:
    """Analyze a single value (check if exists, retrieve or analyze)."""
    if value_exists(init, value, value_type, conn):
        console.print(
            f"[bold yellow]Value already exists in LOCAL database: {value}[/bold yellow]"
        )
        report = get_existing_report(init, value, value_type, conn)
        return [report], 1, 0
    else:
        result = analyze_value(init, value_type, value)
        if result:
            return [result], 0, 0
        else:
            return [], 0, 1


def get_existing_report(init: Initializator, value: str, value_type: str, conn) -> dict:
    """Retrieve existing report for a value from the local database."""
    try:
        value_type_str = validate_value(init, value, value_type)
        if value_type_str and value_type_str not in UNSUPPORTED_VALUE_TYPES:
            return init.db_handler.get_report(value, value_type_str.upper(), conn)
    except Exception as e:
        console.print(
            f"[bold red]Error retrieving existing report for {value_type[:-1]}: {value}[/bold red] - {e}"
        )
    return {}


def value_exists(init: Initializator, value: str, value_type: str, conn) -> bool:
    """Check if a value exists in the local database."""
    if value_type == "hashes":
        return init.db_handler.exists(conn, value_type, value, value_type[:-2])
    else:
        if value_type == "ips":
            return init.db_handler.exists(conn, value_type, value[0], value_type[:-1])
        else:
            return init.db_handler.exists(conn, value_type, value, value_type[:-1])


def analyze_value(init: Initializator, value_type: str, value: str) -> dict:
    """Analyze a single value using VirusTotal API."""
    try:
        value_type_str = validate_value(init, value, value_type)
        if value_type_str and value_type_str not in UNSUPPORTED_VALUE_TYPES:
            return init.reporter.get_report(value_type_str.upper(), value)
        else:
            console.print(f"[bold red]Invalid {value_type[:-1]}: {value}[/bold red]")
    except Exception as e:
        console.print(
            f"[bold red]Error analyzing {value_type[:-1]}: {value}[/bold red] - {e}"
        )
    return None


def validate_value(init: Initializator, value: str, value_type: str) -> str:
    """Validate value based on its type."""
    try:
        if value_type == "hashes":
            return init.validator.validate_hash(value)
        else:
            validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
            return validator_func(value)
    except AttributeError:
        console.print(
            f"[bold red]No validator found for value type: {value_type}[/bold red]"
        )
    return ""


def process_results(init: Initializator, results: List[Dict], value_type: str) -> None:
    """Process and format the analysis results for output to CSV and TXT files."""
    try:
        # Extract headers and rows directly from JSON
        headers, rows = extract_table_data(results)
        # Create formatted table
        table = cpt(headers, rows)
        strtable = table.create_table(
            value_type[:-1] if value_type != "hashes" else "hash"
        )

        # Generate CSV report for the analysis
        output_csv(init, results, value_type)

        # Generate TXT report from the formatted table
        output_txt(init, strtable, value_type)

        # Notify user of successful analysis
        display_analysis_success_message(value_type)

    except Exception as e:
        logging.error(f"Error processing results: {e}")
        console.print(f"[bold red]Error processing results: {e}[/bold red]")


def extract_table_data(results: List[Dict]) -> Tuple[List[str], List[List[str]]]:
    """Extract headers and row values directly from JSON objects."""

    headers = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        headers.update(result["csv_report"][0].keys())

    rows = []
    for result in results:
        if not isinstance(result, dict):
            continue
        rows.append(
            [str(result["csv_report"][0].get(header, "")) for header in headers]
        )

    return list(headers), rows


def output_csv(init: Initializator, results: List[Dict], value_type: str) -> None:
    """Generate and save the CSV report based on the analysis results."""
    try:
        # Collect all CSV reports from the results
        total_csv_report = [result["csv_report"] for result in results]

        # Save CSV report
        init.output.output_to_csv(
            total_csv_report,
            f"{value_type[:-1].upper()}" if value_type != "hashes" else "HASH",
        )
    except Exception as e:
        logging.error(f"Error saving CSV report: {e}")
        console.print(f"[bold red]Error saving CSV report: {e}[/bold red]")


def output_txt(init: Initializator, strtable: str, value_type: str) -> None:
    """Generate and save the TXT report based on the formatted table."""
    try:
        init.output.output_to_txt(
            strtable, f"{value_type[:-1].upper()}" if value_type != "hashes" else "HASH"
        )
    except Exception as e:
        logging.error(f"Error saving TXT report: {e}")
        console.print(f"[bold red]Error saving TXT report: {e}[/bold red]")


def display_analysis_success_message(value_type: str) -> None:
    """Display a message to notify the user that the analysis has completed successfully."""
    console.print(
        Panel(
            Markdown("### Analysis ended successfully"),
            title=f"[bold green]{value_type[:-1].upper()} Analysis[/bold green]",
            border_style="green",
        )
    )


def close_resources(init: Initializator) -> None:
    """Close resources like network connections or database clients."""
    try:
        init.client.close()
    except Exception as e:
        logging.error(f"Error closing resources: {e}")
        console.print(f"[bold red]Error closing resources: {e}[/bold red]")


def main() -> None:
    """Main function to run the script."""
    setup_logging()
    print_welcome_message()
    try:
        args = parse_arguments()
        if args.non_interactive:
            value_type = (
                ["ips", "domains", "urls", "hashes"]
                if args.type == "all"
                else [args.type]
            )
        else:
            value_type = get_user_choice()
        analyze_values(args, value_type)
    except Exception as e:
        logging.error(f"Error during main execution: {e}")
        console.print(f"[bold red]Error during execution: {e}[/bold red]")


if __name__ == "__main__":
    main()
