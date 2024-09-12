import os  # for interacting with the operating system
from datetime import timezone  # for working with dates and times

from rich.console import Console
from rich.prompt import InvalidResponse, Prompt
from rich.table import Table
from rich.text import Text

console = Console()


def utc2local(utc):
    """
    Convert UTC time to local time.

    Parameters:
    utc (datetime): The UTC time to convert.

    Returns:
    datetime: The local time.
    """
    return utc.replace(tzinfo=timezone.utc).astimezone(tz=None)


def get_api_key(api_key: str = None, api_key_file: str = None) -> str:
    """
    Get the API key.

    Parameters:
    api_key (str, optional): The API key.
    api_key_file (str, optional): The file containing the API key.

    Returns:
    str: The API key.
    """
    # Check if API key is provided directly
    if api_key:
        return api_key

    # Check if API key is provided via a file
    elif api_key_file:
        try:
            with open(api_key_file, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            print(f"API key file '{api_key_file}' not found.")
            exit()

    # Check if API key is provided via environment variable
    elif os.getenv("VTAPIKEY"):
        return os.getenv("VTAPIKEY")

    # No API key provided, print error and exit
    else:
        print("No API key provided.")
        exit()


def get_proxy(proxy: str = None) -> str:
    """
    Get the proxy.

    Parameters:
    proxy (str, optional): The proxy.

    Returns:
    str: The proxy.
    """
    # Check if proxy is provided directly
    if proxy:
        return proxy

    # Check if proxy is provided via environment variable
    elif os.getenv("PROXY"):
        return os.getenv("PROXY")

    # No proxy provided, print error and return None
    else:
        print("No Proxy provided.")
        return ""


def display_menu():
    """
    Display the analysis type menu.
    """
    table = Table(title="Analysis Types", title_style="bold yellow")
    table.add_column("Key", justify="center", style="cyan", no_wrap=True)
    table.add_column("Type", justify="center", style="magenta")

    options = {"1": "IPs", "2": "Domains", "3": "URLs", "4": "Hashes"}

    for key, value in options.items():
        table.add_row(key, value)

    console.print(table)


def get_initial_choice():
    """
    Get the initial choice from the user.

    Returns:
    str: The user's initial choice (y/n).
    """
    return (
        Prompt.ask(
            "[bold]Do you want to analyze a particular type? (y/n)[/bold]",
            choices=["y", "n", "yes", "no", "Y", "N"],
            default="n",
        )
        .strip()
        .lower()
    )


def get_analysis_type():
    """
    Get the analysis type from the user.

    Returns:
    str: The analysis type selected by the user.
    """
    while True:
        display_menu()
        choice = (
            Prompt.ask("[bold]Which type do you want to analyze? [/bold]")
            .strip()
            .lower()
        )
        mapping = {"1": "ips", "2": "domains", "3": "urls", "4": "hashes"}
        value_type = mapping.get(choice)
        if value_type:
            return value_type
        console.print(
            "[bold red]Invalid choice. Please select a valid type.[/bold red]"
        )


def get_user_choice():
    """
    Get the user's choice and return the selected value types.

    Returns:
    list: The selected value types.
    """
    try:
        choice = get_initial_choice()

        if choice == "y":
            return [get_analysis_type()]
        return ["ips", "domains", "urls", "hashes"]

    except InvalidResponse:
        console.print("[bold red]Invalid response. Defaulting to all types.[/bold red]")
        return ["ips", "domains", "urls", "hashes"]
