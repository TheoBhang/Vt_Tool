from datetime import timezone     # for working with dates and times
import os                           # for interacting with the operating system

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
    
def get_user_choice():
    """
    Get the user's choice.

    Returns:
    str: The user's choice.
    """
    # Get the user's choice
    choice = input("Do you want to analyze a particular type? (y/n): ").strip().lower()

    if choice == "y":
        mapping = {"ip": "ips", "i": "ips", "domain": "domains", "d": "domains", "url": "urls", "u": "urls", "hash": "hashes", "h": "hashes"}
        choice = input("Which type do you want to analyze? (ip/domain/url/hash): ").strip().lower()
        value_type = mapping.get(choice)
        value_type = [value_type]
        if not value_type:
            print("Invalid choice. Defaulting to all types.")
    elif choice == "n":
        value_type = ["ips", "domains", "urls", "hashes"]
    else:
        print("Invalid choice. Defaulting to all types.")
        value_type = ["ips", "domains", "urls", "hashes"]
    
    return value_type