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