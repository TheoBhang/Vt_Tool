import argparse
import logging
from datetime import datetime

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from app.DataHandler.utils import get_api_key, get_proxy, get_user_choice
from app.FileHandler.create_table import CustomPrettyTable as cpt
from app.FileHandler.read_file import ValueReader
from app.MISP.vt_tools2misp import misp_choice
from init import Initializator

console = Console()


def setup_logging() -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )


def print_welcome_message() -> None:
    """Print the welcome message with ASCII art and title."""
    ascii_art = Text(
        """
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

    title = Text(
        """
  _      __      __                        __          _   __ __    ______            __   
 | | /| / /___  / /____ ___   __ _  ___   / /_ ___    | | / // /_  /_  __/___  ___   / /___
 | |/ |/ // -_)/ // __// _ \ /  ' \/ -_) / __// _ \   | |/ // __/   / /  / _ \/ _ \ / /(_-<
 |__/|__/ \__//_/ \__/ \___//_/_/_/\__/  \__/ \___/   |___/ \__/   /_/   \___/\___//_//___/
 """,
        justify="center",
        style="bold yellow",
    )

    console.print(title)

    subtitle = Text(
        """
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
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input_file", "-f", type=str, help="Input file containing values to analyze."
    )
    parser.add_argument(
        "--case_id",
        "-c",
        type=str,
        help="ID for the case to create (Or MISP event UUID to create or update)",
    )
    parser.add_argument(
        "--api_key", "-a", type=str, help="VirusTotal API key, default VTAPIKEY env var"
    )
    parser.add_argument(
        "--api_key_file", "-af", type=str, help="VirusTotal API key in a file."
    )
    parser.add_argument("--proxy", "-p", type=str, help="Proxy to use for requests.")
    parser.add_argument(
        "values",
        type=str,
        nargs="*",
        help="The values to analyze. Can be IP addresses, hashes, URLs, or domains.",
    )
    return parser.parse_args()


def get_remaining_quota(api_key: str, proxy: str = None) -> int:
    """Returns the number of hashes that could be queried within this run."""
    url = f"https://www.virustotal.com/api/v3/users/{api_key}/overall_quotas"
    headers = {"Accept": "application/json", "x-apikey": api_key}
    response = requests.get(
        url, headers=headers, proxies={"http": proxy, "https": proxy}
    )

    if response.status_code == 200:
        json_response = response.json()
        allowed_hourly_queries = json_response["data"]["api_requests_hourly"]["user"][
            "allowed"
        ]
        used_hourly_queries = json_response["data"]["api_requests_hourly"]["user"][
            "used"
        ]
        return allowed_hourly_queries - used_hourly_queries
    else:
        logging.error(
            "Error retrieving VT Quota (HTTP Status code: %d)", response.status_code
        )
        return 0


def count_iocs(ioc_dict):
    total_iocs = 0
    for key, value in ioc_dict.items():
        total_iocs += len(value)
    return total_iocs


def analyze_values(args: argparse.Namespace, value_types: list[str]) -> None:
    """Analyze values provided as arguments."""
    load_dotenv()
    api_key = get_api_key(args.api_key, args.api_key_file)
    proxy = get_proxy(args.proxy)
    case_id = str(args.case_id or 0).zfill(6)

    init = Initializator(api_key, proxy, case_id)

    database = "vttools.sqlite"
    quota_saved = 0

    with init.db_handler.create_connection(database) as conn:
        if conn is not None:
            init.db_handler.create_schema(conn)

        start_time = datetime.now()
        console.print("\n[bold blue]Checking for remaining queries...[/bold blue]")
        remaining_queries = get_remaining_quota(init.api_key, init.proxy)

        if remaining_queries == 0:
            console.print(
                "[bold yellow]No queries remaining for this hour.[/bold yellow]"
            )
            console.print("[bold blue]Check your API key before analysis.[/bold blue]")
            console.print("[bold green]Thank you for using VT Tools! 👍[/bold green]")
            return

        console.print(f"Remaining queries for this hour: {remaining_queries}")
        values = ValueReader(args.input_file, args.values).read_values()

        if not values:
            console.print("[bold yellow]No values to analyze.[/bold yellow]")
            console.print("Thank you for using VT Tools! [bold green]👍[/bold green]")
            return

        console.print(
            f"[bold blue]This analysis will use {count_iocs(values)} out of your {remaining_queries} hourly quota.[/bold blue]\n"
        )

        if remaining_queries < count_iocs(values):
            console.print(
                f"[bold yellow]Warning:[/bold yellow] You have {remaining_queries} queries left for this hour, but you are trying to analyze {len(values)} values."
            )
            console.print(
                "[bold yellow]Some values may be skipped to avoid exceeding the quota.[/bold yellow]\n"
            )
            console.print("Thank you for using VT Tools! [bold green]👍[/bold green]")
            return

        for value_type in value_types:
            if not values.get(value_type):
                console.print(
                    f"[bold yellow]No {value_type[:-1].upper()} values to analyze.[/bold yellow]"
                )
                console.print("\n")
                continue

            console.print(
                Panel(
                    Markdown("## Analysis Started"),
                    title=f"[bold green]{value_type[:-1].upper()} Analysis[/bold green]",
                    border_style="green",
                )
            )
            results, skipped_values, error_values = analyze_value_type(
                init, value_type, values[value_type], conn
            )
            quota_saved += skipped_values

            if results:
                process_results(init, results, value_type)

        csv_files_created = list(set(init.output.csvfilescreated))
        quota_final = get_remaining_quota(init.api_key, init.proxy)
        if quota_saved == 0:
            console.print(
                "[bold green]Analysis completed. No values were skipped.[/bold green]"
            )
        elif quota_saved == 1:
            console.print(
                "[bold green]Analysis completed. 1 value was skipped as it already exists in the database.[/bold green]"
            )
        else:
            console.print(
                f"[bold green]Analysis completed. {quota_saved} values were skipped as they already exist in the database.[/bold green]"
            )
        console.print(f"[bold blue]Errors occurred for {error_values} values.[/bold blue]")
        console.print(f"[bold yellow]Remaining queries for this hour: {quota_final}[/bold yellow]")
        total_time = datetime.now() - start_time
        console.print(f"[bold blue]Total time taken: {total_time}[/bold blue]")

        misp_choice(case_str=case_id, csvfilescreated=csv_files_created)
        console.print("[bold green]Thank you for using VT Tools!👍[/bold green]")
        close_resources(init)


def analyze_value_type(
    init: Initializator, value_type: str, values: list[str], conn
):
    """Analyze values of a specific type."""
    results = []
    skipped_values = 0
    error_values = 0

    for value in values:
        if value_exists(init, value, value_type, conn):
            console.print(
                f"[bold yellow]Value already exists in LOCAL database: {value}[/bold yellow]"
            )
            results.append(get_existing_report(init, value, value_type, conn))
            skipped_values += 1
        else:
            result = analyze_value(init, value_type, value)
            if result:
                results.append(result)
            else:
                error_values += 1

    return results, skipped_values, error_values


def get_existing_report(init: Initializator, value: str, value_type: str, conn) -> dict:
    """Retrieve existing report for a value from the local database."""
    try:
        if value_type == "hashes":
            value_type_str = init.validator.validate_hash(value)
        else:
            validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
            value_type_str = validator_func(value)

        if value_type_str and value_type_str not in [
            "Private IPv4",
            "Loopback IPv4",
            "Unspecified IPv4",
            "Link-local IPv4",
            "Reserved IPv4",
            "SHA-224",
            "SHA-384",
            "SHA-512",
            "SSDEEP",
        ]:
            return init.db_handler.get_report(value, value_type_str.upper(), conn)
    except Exception as e:
        console.print(
            f"[bold red]Error retrieving existing report for {value_type[:-1]}: {value}[/bold red]"
        )


def value_exists(init: Initializator, value: str, value_type: str, conn) -> bool:
    """Check if a value exists in the local database."""
    check_funcs = {
        "hashes": init.db_handler.hash_exists,
        "urls": init.db_handler.url_exists,
        "domains": init.db_handler.domain_exists,
        "ips": init.db_handler.ip_exists,
    }
    return check_funcs.get(value_type, lambda *args: False)(value, conn)


def analyze_value(init: Initializator, value_type: str, value: str) -> dict:
    """Analyze a single value using VirusTotal API."""
    try:
        if value_type == "hashes":
            value_type_str = init.validator.validate_hash(value)
        else:
            validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
            value_type_str = validator_func(value)

        if value_type_str and value_type_str not in [
            "Private IPv4",
            "Loopback IPv4",
            "Unspecified IPv4",
            "Link-local IPv4",
            "Reserved IPv4",
            "SHA-224",
            "SHA-384",
            "SHA-512",
            "SSDEEP",
        ]:
            return init.reporter.get_report(value_type_str.upper(), value)
        else:
            console.print(f"[bold red]Invalid {value_type[:-1]}: {value}[/bold red]")
    except Exception as e:
        console.print(
            f"[bold red]Error analyzing {value_type[:-1]}: {value}[/bold red]"
        )

    return None


def process_results(init: Initializator, results: list[dict], value_type: str) -> None:
    """Process the analysis results."""
    header_rows = []
    value_rows = []

    for result in results:
        if result:
            for row in result["rows"]:
                if row[0] not in header_rows:
                    header_rows.append(row[0])
                value_rows.append(row[1:])

    table = cpt(header_rows, value_rows)
    strtable = table.create_table()

    total_csv_report = [result["csv_report"] for result in results]
    init.output.output_to_csv(
        total_csv_report, "HASH" if value_type == "hashes" else value_type[:-1].upper()
    )
    init.output.output_to_txt(
        strtable, "HASH" if value_type == "hashes" else value_type[:-1].upper()
    )
    console.print(
        Panel(
            Markdown("### Analysis ended successfully"),
            title=f"[bold green]{value_type[:-1].upper()} Analysis[/bold green]",
            border_style="green",
        )
    )


def close_resources(init: Initializator) -> None:
    """Close resources."""
    init.client.close()


def main() -> None:
    """Main function to run the script."""
    setup_logging()
    print_welcome_message()
    args = parse_arguments()
    value_type = get_user_choice()
    analyze_values(args, value_type)


if __name__ == "__main__":
    main()
