from datetime import datetime       # for working with dates and times
import time                         # for creating countdown timers
import os                           # for interacting with the operating system

def utc2local(utc):
    """
    Convert UTC time to local time.

    Parameters:
    utc (datetime): The UTC time to convert.

    Returns:
    datetime: The local time.
    """
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset

def get_api_key(api_key: str, api_key_file: str) -> str:
    """
    Get the API key.

    Parameters:
    api_key (str): The API key.
    api_key_file (str): The file containing the API key.

    Returns:
    str: The API key.
    """
    # Get the API key
    if api_key:
        return api_key
    elif api_key_file:
        with open(api_key_file, "r") as f:
            return f.read().strip()
    elif os.getenv("VTAPIKEY"):
        return os.getenv("VTAPIKEY")
    else:
        print("No API key provided.")
        exit()

def get_proxy(proxy: str) -> str:
    """
    Get the proxy.

    Parameters:
    proxy(str): The proxy.
    Returns:
    str: The proxy.
    
    """
    if proxy:
        return proxy
    elif os.getenv("PROXY"):
        return os.getenv("PROXY")
    else:
        print("No Proxy provided.")
        return None
    
def get_user_choice():
    """
    Get the user's choice.

    Returns:
    str: The user's choice.
    """
    # Get the user's choice
    choice = input("Do you want to analyse a particular type ? (y/n) : ")

    if choice == "y" or choice == "Y":
        choice = input("Which type do you want to analyse ? \n\td = Domain\n\th = Hash\n\ti = Ip\n\tu = Url\nYour choice : ")
        if choice == "ip" or choice == "i" or choice == "IP" or choice == "I":
            value_type = "ips"
        elif choice == "domain" or choice == "d" or choice == "DOMAIN" or choice == "D":
            value_type = "domains"
        elif choice == "url" or choice == "u" or choice == "URL" or choice == "U":
            value_type = "urls"
        elif choice == "hash" or choice == "h" or choice == "HASH" or choice == "H":
            value_type = "hashes"
        else:
            print("Invalid choice.")
            print("Defaulting to all types.")
            value_type = None
    elif choice == "n" or choice == "N":
        value_type = None
    else:
        print("Invalid choice.")
        print("Defaulting to all types.")
        value_type = None
    
    return value_type