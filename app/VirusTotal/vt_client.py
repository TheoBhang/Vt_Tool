import vt                           # for interacting with VirusTotal API V3

class VirusTotalClient:
    """
    A class for interacting with the VirusTotal API.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.

    Methods:
    initClient(self): Initialize the VirusTotal client.

    """

    def __init__(self, api_key: str, proxy: str = None):
        self.api_key = api_key
        self.proxy = proxy

    def initClient(self):
        # Initialize the VirusTotal client
        client = vt.Client(self.api_key, proxy=self.proxy)

        return client  # Return the client

        