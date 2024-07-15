import vt  # for interacting with VirusTotal API V3


class VirusTotalClient:
    """
    A class for interacting with the VirusTotal API.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.

    Methods:
    init_client(self): Initialize the VirusTotal client.

    """

    def __init__(self, api_key: str, proxy: str = None):
        """
        Initialize the VirusTotalClient.

        Parameters:
        api_key (str): The VirusTotal API key.
        proxy (str): The proxy to use for requests. Defaults to None.
        """
        self.api_key = api_key
        self.proxy = proxy

    def init_client(self) -> vt.Client:
        """
        Initialize the VirusTotal client.

        Returns:
        vt.Client: The initialized VirusTotal client.
        """
        try:
            # Initialize the VirusTotal client
            client = vt.Client(self.api_key, proxy=self.proxy)
            return client
        except vt.APIError as e:
            # Handle API error
            print(f"Error initializing VirusTotal client: {e}")
            return None
        except Exception as e:
            # Handle other exceptions
            print(f"Unexpected error initializing VirusTotal client: {e}")
            return None
