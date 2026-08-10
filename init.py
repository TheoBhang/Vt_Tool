import os
from datetime import timedelta

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from app.VirusTotal.vt_client import VirusTotalClient
from app.DataHandler.validator import DataValidator
from app.FileHandler.output_to_file import OutputHandler
from app.services.validation_service import ValidationService
from app.services.virustotal_service import VirusTotalService
from app.services.cache_service import ReportCacheService, DEFAULT_TTL_HOURS
from app.services.analysis_service import AnalysisService
from app.services.misp_service import MispService
from app.cache_backends.sqlite_backend import SQLiteCacheBackend

console = Console()

DATABASE_FILE = "vttools.sqlite"


class Initializator:
    """
    Wires up the service factory for a single vt_tool run.

    Attributes:
        api_key (str): VirusTotal API key.
        proxy (str, optional): Proxy for API requests.
        case_num (str, optional): Case identifier for logging/output.
        client (vt.Client): VirusTotal API client instance.
        analysis (AnalysisService): The core "analyze one value" orchestrator.
        misp (MispService): MISP object-building service.
        output (OutputHandler): Manages output file handling.
    """

    def __init__(self, api_key: str, proxy: str = None, case_num: str = None):
        self.api_key = api_key
        self.proxy = proxy
        self.case_num = case_num

        self.client = self._init_client()
        cache_backend = SQLiteCacheBackend(DATABASE_FILE)
        cache_ttl = timedelta(hours=float(os.getenv("VT_CACHE_TTL_HOURS", str(DEFAULT_TTL_HOURS))))
        self.analysis = AnalysisService(
            validation=ValidationService(DataValidator()),
            virustotal=VirusTotalService(self.client),
            cache=ReportCacheService(cache_backend, ttl=cache_ttl),
        )
        self.misp = MispService()
        self.output = OutputHandler(self.case_num)

        self._display_info(self.client, self.analysis, self.misp, self.output)

    def _init_client(self):
        """Initializes the VirusTotal client."""
        return VirusTotalClient(self.api_key, self.proxy).init_client()

    def _display_info(self, client, analysis, misp, output):
        """Displays information about the initialized components with a clear UI."""

        console.print(Panel(Text("Initialized Components", style="bold magenta"), expand=False))

        components = {
            "VirusTotal Client": client,
            "Analysis Service": analysis,
            "MISP Service": misp,
            "Output Handler": output,
        }

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Component", style="bold white")
        table.add_column("Status", justify="center", style="bold")

        for name, status in components.items():
            status_text = "[green]✅ Initialized[/green]" if status else "[red]❌ Not initialized[/red]"
            table.add_row(name, status_text)

        console.print(table)

        console.print(Panel(Text("Initialization Complete ✅", style="bold green"), expand=False))
