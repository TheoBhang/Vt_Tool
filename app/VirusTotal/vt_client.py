import vt  # for interacting with VirusTotal API V3
import logging


# Set up logging for better debugging and tracking of issues
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VirusTotalClient:
    """
    A class for interacting with the VirusTotal API.

    Attributes:
        api_key (str): The VirusTotal API key.
        proxy (str): The proxy to use for requests (optional).

    Methods:
        init_client(self): Initializes the VirusTotal client.
        get_report(self, resource_id: str): Fetches the report for a specific resource (e.g., URL, file hash).
    """

    def __init__(self, api_key: str, proxy: str = None, verify_ssl: bool = True):
        """
        Initializes the VirusTotalClient with the provided API key and optional proxy.

        Parameters:
            api_key (str): The VirusTotal API key.
            proxy (str): The proxy to use for requests (optional).
            verify_ssl (bool): Whether to verify VirusTotal's TLS certificate (default: True).
        """
        self.api_key = api_key
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.client = None

    def init_client(self) -> bool:
        """
        Initializes the VirusTotal client.

        Returns:
            bool: True if the client was initialized successfully, False otherwise.
        """
        try:
            self.client = vt.Client(self.api_key, proxy=self.proxy, verify_ssl=self.verify_ssl)
            return self.client
        except vt.APIError as e:
            logger.error(f"APIError initializing VirusTotal client: {e}")
        except Exception as e:
            logger.error(f"Unexpected error initializing VirusTotal client: {e}")

        return False
