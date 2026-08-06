import logging
from vt import url_id  # for interacting with URLs in VirusTotal
from app.DataHandler.utils import utc2local, build_virustotal_link  # for converting UTC time to local time
from app.DBHandler.db_handler import DBHandler
from app.DataHandler.validator import get_service_name, get_url_details, extract_ip_address, get_port_from_service_name
# Constants for handling various types and error messages
IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = "No https certificate found"

# Set up logging for better debugging and tracking of issues
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VTReporter:
    """
    A class to generate reports from VirusTotal for different value types.

    Attributes:
        vt (object): The VirusTotal client instance.

    Methods:
        create_report(value_type: str, value: str) -> dict:
            Creates and fetches a report for a given value type (e.g., IP, URL, SHA256).
    """

    def __init__(self, vt):
        """
        Initializes the VTReporter with the provided VirusTotal client.

        Parameters:
            vt (object): The initialized VirusTotal client.
        """
        self.vt = vt

    def create_report(self, value_type: str, value: str) -> dict:
        """
        Create a report for a given value (e.g., IP, URL, hash).

        Parameters:
            value_type (str): The type of value (e.g., IPV4, DOMAIN, URL, SHA-256).
            value (str): The value for which the report will be created (e.g., IP, URL, hash).

        Returns:
            dict: The report data from VirusTotal.
        """
        if isinstance(value, tuple):
            value = value[0]
        # Define API endpoints for different value types
        api_endpoints = {
            IPV4_PUBLIC_TYPE: f"/ip_addresses/{value}",
            "DOMAIN": f"/domains/{value}",
            "URL": f"/urls/{url_id(value)}",
            "SHA-256": f"/files/{value}",
            "SHA-1": f"/files/{value}",
            "MD5": f"/files/{value}",
        }
        # Initialize report
        report = None
        # Ensure valid value_type and value are provided
        if value_type not in api_endpoints:
            return None
        try:
            # Fetch the report from VirusTotal
            report = self.vt.get_object(api_endpoints[value_type])
        except Exception as e:
            # Handle errors such as not found
            if "NotFoundError" in str(e):
                report = NOT_FOUND_ERROR
                logger.warning(f"{NOT_FOUND_ERROR} on VirusTotal Database: {value}")
            else:
                logger.error(f"Error fetching report for {value_type}: {value} - {e}")
                raise e
        return report if report else None

    def create_object(self, value_type, value, report):
        """
        Creates and populates an object for a given value from VirusTotal data.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value (str): The value for which to create the object (e.g., IP address, hash, URL).
            report (dict): The VirusTotal report for the value.

        Returns:
            dict: A dictionary with the populated data.
        """
        value_object = self.initialize_value_object(value_type)

        if report != NOT_FOUND_ERROR and report:
            self.populate_value_object(value_object, value_type, value, report)

            # Determine where to insert based on value type
            self.insert_into_db(value_type, value_object)

        return value_object

    def initialize_value_object(self, value_type):
        """
        Initializes a value object based on the value type.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)

        Returns:
            dict: An initialized value object with default values.
        """
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "tags": NOT_FOUND_ERROR,
            "link": NOT_FOUND_ERROR,
        }

        # Add specific fields for hash types
        if value_type in ["SHA-256", "SHA-1", "MD5"]:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR

        return value_object

    def populate_value_object(self, value_object, value_type, value, report):
        """
        Populates the value object with data from the VirusTotal report.

        Parameters:
            value_object (dict): The object to populate.
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value (str): The value (e.g., IP address, hash, URL).
            report (dict): The VirusTotal report for the value.
        """
        # check if report is empty
        if report == {}:
            total_scans = 0
            malicious = 0
        else:
            total_scans = sum(report.last_analysis_stats.values())
            malicious = report.last_analysis_stats.get("malicious", 0)

        self.populate_scores(value_object, total_scans, malicious)
        value_object["link"] = build_virustotal_link(value, value_type)
        self.populate_tags(value_object, report)

        # Populate additional fields based on value type
        if value_type == IPV4_PUBLIC_TYPE:
            self.populate_ip_data(value_object, value, report)
        elif value_type == "DOMAIN":
            self.populate_domain_data(value_object, value, report)
        elif value_type == "URL":
            self.populate_url_data(value_object, value, report)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            self.populate_hash_data(value_object, value, report)
            try:
                if report.popular_threat_classification:
                    popular_threat_classification = report.get("popular_threat_classification", {})

                    suggested_threat_label = popular_threat_classification.get("suggested_threat_label", NOT_FOUND_ERROR)
                    popular_threat_category = popular_threat_classification.get('popular_threat_category', [])

                    # Concaténer les valeurs en une seule chaîne de caractères
                    categories_str = ", ".join(category['value'] for category in popular_threat_category)
                    if report.popular_threat_classification:
                        value_object["threat_category"] = categories_str
                        value_object["threat_labels"] = suggested_threat_label
                else:
                    value_object["threat_category"] = NOT_FOUND_ERROR
                    value_object["threat_labels"] = NOT_FOUND_ERROR
            except:
                value_object["threat_category"] = NOT_FOUND_ERROR
                value_object["threat_labels"] = NOT_FOUND_ERROR

    def insert_into_db(self, value_type, value_object):
        """
        Inserts the value object into the appropriate database table.

        Parameters:
            value_type (str): The type of value (e.g., "SHA-256", "IPV4", etc.)
            value_object (dict): The value object to insert.
        """
        database = "vttools.sqlite"
        conn = DBHandler().create_connection(database)

        if value_type == IPV4_PUBLIC_TYPE:
            DBHandler().insert_ip_data(conn, value_object)
        elif value_type == "DOMAIN":
            DBHandler().insert_domain_data(conn, value_object)
        elif value_type == "URL":
            DBHandler().insert_url_data(conn, value_object)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            DBHandler().insert_hash_data(conn, value_object)

    def populate_tags(self, value_object, report):
        """Populates the 'tags' field from the VirusTotal report."""
        tags = getattr(report, "tags", [])
        value_object["tags"] = ", ".join(tags) if tags else NOT_FOUND_ERROR

    def populate_scores(self, value_object, total_scans, malicious):
        """Populates the 'malicious_score' and 'total_scans' fields."""
        value_object["malicious_score"] = malicious
        value_object["total_scans"] = total_scans

    def populate_ip_data(self, value_object, value, report):
        """Populates the IP-specific fields."""
        if isinstance(value, tuple):
            ip, port = value
        else:
            ip = value
            port = None
        value_object.update({
            "ip": ip,
            "port": port if port else NOT_FOUND_ERROR,
            "protocol": get_service_name(port) if port else NOT_FOUND_ERROR,
            "owner": getattr(report, "as_owner", NOT_FOUND_ERROR),
            "location": f"{report.continent} / {report.country}" if hasattr(report, "continent") and hasattr(report, "country") else NOT_FOUND_ERROR,
            "network": getattr(report, "network", NOT_FOUND_ERROR),
            "https_certificate": getattr(report, "last_https_certificate", NOT_FOUND_ERROR),
            "info-ip": {
                "regional_internet_registry": getattr(report, "regional_internet_registry", NOT_FOUND_ERROR),
                "asn": getattr(report, "asn", NOT_FOUND_ERROR),
            }
        })

    def populate_domain_data(self, value_object, value, report):
        """Populates the domain-specific fields."""
        ip = getattr(report, "whois", {})
        if isinstance(ip, str):
            ip = extract_ip_address(ip)
        value_object.update({
            "domain": value,
            "ip": ip if ip else NOT_FOUND_ERROR,
            "port": getattr(report, "port", NOT_FOUND_ERROR),
            "protocol": get_service_name(getattr(report, "port", None)) if getattr(report, "port", None) else NOT_FOUND_ERROR,
            "creation_date": getattr(report, "creation_date", NOT_FOUND_ERROR),
            "reputation": getattr(report, "reputation", NOT_FOUND_ERROR),
            "whois": getattr(report, "whois", NOT_FOUND_ERROR),
            "info": {
                "last_analysis_results": getattr(report, "last_analysis_results", NOT_FOUND_ERROR),
                "last_analysis_stats": getattr(report, "last_analysis_stats", NOT_FOUND_ERROR),
                "last_dns_records": getattr(report, "last_dns_records", NOT_FOUND_ERROR),
                "last_https_certificate": getattr(report, "last_https_certificate", NOT_FOUND_ERROR),
                "registrar": getattr(report, "registrar", NOT_FOUND_ERROR),
            },
        })

    def populate_url_data(self, value_object, value, report):
        """Populates the URL-specific fields."""
        details = get_url_details(value)
        first_submission_date = getattr(report, "first_submission_date", None)
        if first_submission_date:
            try:
                first_scan = str(utc2local(first_submission_date))
            except Exception as e:
                logger.error(f"Date was not found: {e}")
                first_scan = NOT_FOUND_ERROR
        else:
            first_scan = NOT_FOUND_ERROR

        if not details["port"]:
            port = get_port_from_service_name(details["scheme"])
            print(f"Port from service name: {port}")
        else:
            port = details["port"]
            print(f"Port from details: {port}")

        value_object.update({
            "url": value,
            "domain": details["domain"] if details["domain"] !='' else NOT_FOUND_ERROR,
            "ip": getattr(report, "ip_address", NOT_FOUND_ERROR),
            "port": port,
            "protocol": get_service_name(details["port"]) if details["port"] !='' else NOT_FOUND_ERROR,
            "fragment": details["fragment"] if details["fragment"] !='' else NOT_FOUND_ERROR,
            "resource_path": details["resource_path"] if details["resource_path"] !='' else NOT_FOUND_ERROR,
            "query_params": details["query_params"] if details["query_params"] !='' else NOT_FOUND_ERROR,
            "query_strings": details["query_strings"] if details["query_strings"] !='' else NOT_FOUND_ERROR,
            "tld": details["tld"] if details["tld"] !='' else NOT_FOUND_ERROR,
            "subdomain": details["subdomain"] if details["subdomain"] !='' else NOT_FOUND_ERROR,
            "scheme": details["scheme"] if details["scheme"] !='' else NOT_FOUND_ERROR,
            "title": getattr(report, "title", NOT_FOUND_ERROR),
            "final_url": getattr(report, "last_final_url", NOT_FOUND_ERROR),
            "first_scan": first_scan,
            "info": {
                "metadatas": getattr(report, "html_meta", NOT_FOUND_ERROR),
                "targeted": getattr(report, "targeted_brand", NOT_FOUND_ERROR),
                "links": getattr(report, "outgoing_links", NOT_FOUND_ERROR),
                "redirection_chain": getattr(report, "redirection_chain", NOT_FOUND_ERROR),
                "trackers": getattr(report, "trackers", NOT_FOUND_ERROR),
            },
        })

    def populate_hash_data(self, value_object, value, report):
        """Populates the hash-specific fields."""
        value_object.update({
            "hash": value,
            "extension": getattr(report, "type_extension", NOT_FOUND_ERROR),
            "size": getattr(report, "size", NOT_FOUND_ERROR),
            "md5": getattr(report, "md5", NOT_FOUND_ERROR),
            "sha1": getattr(report, "sha1", NOT_FOUND_ERROR),
            "sha256": getattr(report, "sha256", NOT_FOUND_ERROR),
            "ssdeep": getattr(report, "ssdeep", NOT_FOUND_ERROR),
            "tlsh": getattr(report, "tlsh", NOT_FOUND_ERROR),
            "meaningful_name": getattr(report, "meaningful_name", NOT_FOUND_ERROR),
            "names": ", ".join(getattr(report, "names", [NOT_FOUND_ERROR])),
            "type": report.trid[0]["file_type"] if hasattr(report, "trid") else NOT_FOUND_ERROR,
            "type_probability": report.trid[0]["probability"] if hasattr(report, "trid") else NOT_FOUND_ERROR,
        })

    def get_rows(self, value_type, value, report):
        """
        Get the rows for a value and its report.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the rows for.
        report (dict): The report for the value.

        Returns:
        List[List[str]]: The rows for the value and its report.
        """
        # Create the object for the value
        row_object = self.create_object(value_type, value, report)

        if report != NOT_FOUND_ERROR:
            # Clean up the 'info' key if it exists
            row_object.pop("info", None)

            # Construct rows from the row object
            rows = [[key, value] for key, value in row_object.items()]

            # Append standard rows for votes and other metadata
            standard_rows = [
                ["VirusTotal Total Votes", getattr(report, "total_votes", "No total votes found")]
            ]
            rows.extend(standard_rows)

            return rows
        return []

    def csv_report(self, value_type, value, report):
        """
        Create a CSV report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.
        report (dict): The report for the value.

        Returns:
        List[Dict[str, str]]: The CSV report for the value.
        """
        # Create the object to use for the CSV
        csv_object = self.create_object(value_type, value, report)

        # Return the CSV in a list format
        return [csv_object]


    def csv_emtpy_report(self, value_type, value):
        """
        Create an empty CSV report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.

        Returns:
        List[Dict[str, str]]: The empty CSV report for the value.
        """
        # Create the object to use for the CSV
        csv_object = self.create_empty_object(value_type, value)

        # Return the CSV in a list format
        return [csv_object]


    def create_empty_object(self, value_type, value):
        """
        Create an empty object for a given value type.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create the object for.

        Returns:
        dict: The empty object for the value.
        """
        # Initialize the object with default values
        empty_object = self.initialize_value_object(value_type)

        self.populate_value_object(empty_object, value_type, value, {})

        self.insert_into_db(value_type, empty_object)

        return empty_object


    def get_report(self, value_type, value):
        """
        Get the report for a value, generating the CSV and rows.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value along with its CSV and row data.
        """
        # Generate the report using an external method
        report = self.create_report(value_type, value)
        if report:
            if report == NOT_FOUND_ERROR:
                return {
                    "report": {},
                    "csv_report": self.csv_emtpy_report(value_type, value),
                    "rows": []
                }

            # Generate CSV and rows
            csv_report = self.csv_report(value_type, value, report)
            rows = self.get_rows(value_type, value, report)

            # Return all results in a dictionary
            return {
                "report": report,
                "csv_report": csv_report,
                "rows": rows
            }

        return None
