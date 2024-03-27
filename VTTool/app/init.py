from .VirusTotal.vt_reporter import VTReporter
from .VirusTotal.vt_client import VirusTotalClient
from .DataHandler.validator import DataValidator
from .FileHandler.output_to_file import OutputHandler

class Initializator:
    """
    A class for initializing the VirusTotal client.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.
    client (vt.Client): The VirusTotal client.
    reporter (VirusTotalReporter): The VirusTotal reporter.
    validator (DataValidator): The data validator.
    output (OutputHandler): The output handler.

    """
    def __init__(self, api_key: str, proxy: str = None, case_num: str = None):
        self.api_key = api_key
        self.proxy = proxy
        self.client = VirusTotalClient(self.api_key, self.proxy).initClient()
        self.reporter = VTReporter(self.client)
        self.validator = DataValidator()
        self.output = OutputHandler(case_num)

