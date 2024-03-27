from vt import url_id               # for interacting with urls in VirusTotal
from ..DataHandler.utils import utc2local       # for converting UTC time to local time

IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = 'No https certificate found'

class VTReporter:
    def __init__(self, vt):
        self.vt = vt
    
    def create_report(self, value_type, value):
        """
        Create a report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create a report for.

        Returns:
        dict: The report for the value.
        """
        # Define API endpoints for different value types
        api_endpoints = {
            IPV4_PUBLIC_TYPE: f"/ip_addresses/{value}",
            "DOMAIN": f"/domains/{value}",
            "URL": f"/urls/{url_id(value)}",
            "SHA-256": f"/files/{value}"
        }

        # Initialize report
        report = None

        # Get object from VirusTotal for the corresponding value type
        try:
            report = self.vt.get_object(api_endpoints.get(value_type))
        except Exception as e:
            if "NotFoundError" in str(e):
                report = NOT_FOUND_ERROR
            else:
                raise e

        return report

    def create_object(self, value_type, value, report):
        """
        Create an object for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to create an object for.
        report (dict): The report for the value.

        Returns:
        dict: The object for the value.
        """
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "suspicious_score": NOT_FOUND_ERROR,
            "safe_score": NOT_FOUND_ERROR,
            "link": NO_LINK
        }
        
        if report != NOT_FOUND_ERROR:
            total_scans = sum(report.last_analysis_stats.values())
            malicious = report.last_analysis_stats.get("malicious", 0)
            suspicious = report.last_analysis_stats.get("suspicious", 0)
            undetected = report.last_analysis_stats.get("undetected", 0)
            harmless = report.last_analysis_stats.get("harmless", 0)
            self.populate_scores(value_object, total_scans, malicious, suspicious, undetected, harmless)
            self.populate_link(value_object, value)

            if value_type == IPV4_PUBLIC_TYPE:
                self.populate_ip_data(value_object, value, report)
            elif value_type == "DOMAIN":
                self.populate_domain_data(value_object, value, report)
            elif value_type == "URL":
                self.populate_url_data(value_object, value, report)
            elif value_type == "SHA-256":
                self.populate_sha256_data(value_object, value, report)

        return value_object

    def populate_scores(self, value_object, total_scans, malicious, suspicious, undetected, harmless):
        value_object["malicious_score"] = f"{malicious} \\ {total_scans}"
        value_object["suspicious_score"] = f"{suspicious} \\ {total_scans}"
        value_object["safe_score"] = f"{harmless} \\ {total_scans}"
        value_object["undetected_score"] = f"{undetected} \\ {total_scans}"

    def populate_link(self, value_object, value):
        value_object["link"] = f"https://www.virustotal.com/gui/search/{value}"

    def populate_ip_data(self, value_object, value, report):
        value_object.update({
            "IP Address": value,
            "owner": getattr(report, 'as_owner', 'No owner found'),
            "location": f"{report.continent} / {report.country}" if hasattr(report, 'continent') and hasattr(report, 'country') else NOT_FOUND_ERROR,
            "network": getattr(report, 'network', 'No network found'),
            "https_certificate": getattr(report, 'last_https_certificate', NO_HTTP_CERT),
            "info-ip": {
                "regional_internet_registry": getattr(report, 'regional_internet_registry', 'No regional internet registry found'),
                "asn": getattr(report, 'asn', 'No asn found'),
            }
        })

    def populate_domain_data(self, value_object, value, report):
        value_object.update({
            "Domain": value,
            "creation_date": getattr(report, 'creation_date', 'No creation date found'),
            "reputation": getattr(report, 'reputation', 'No reputation found'),
            "whois": getattr(report, 'whois', 'No whois found'),
            "info": {
                'last_analysis_results': getattr(report, 'last_analysis_results', 'No analysis results found'),
                'last_analysis_stats': getattr(report, 'last_analysis_stats', 'No analysis stats found'),
                'last_dns_records': getattr(report, 'last_dns_records', 'No dns records found'),
                'last_https_certificate': NO_HTTP_CERT,
                'registrar': getattr(report, 'registrar', 'No registrar found'),
            }
        })

    def populate_url_data(self, value_object, value, report):
        value_object.update({
            "URL": value,
            "title": getattr(report, 'title', 'No Title Found'),
            "final_Url": getattr(report, 'last_final_url', 'No endpoints'),
            "first_scan": str(utc2local(getattr(report, 'first_submission_date', 'No date Found'))),
            "info": {
                'metadatas': getattr(report, 'html_meta', 'No metadata Found'),
                'targeted': getattr(report, 'targeted_brand', 'No target brand Found'),
                'links': getattr(report, 'outgoing_links', 'No links in url'),
                'redirection_chain': getattr(report, 'redirection_chain', 'No redirection chain Found'),
                'trackers': getattr(report, 'trackers', 'No tracker Found'),
            }
        })

    def populate_sha256_data(self, value_object, value, report):
        value_object.update({
            "Hash (Sha256)": value,
            "extension": getattr(report, 'type_extension', 'No extension found'),
            "Size (Bytes)": getattr(report, 'size', 'No size found'),
            "md5": getattr(report, 'md5', 'No md5 found'),
            "sha1": getattr(report, 'sha1', 'No sha1 found'),
            "ssdeep": getattr(report, 'ssdeep', 'No ssdeep found'),
            "tlsh": getattr(report, 'tlsh', 'No tlsh found'),
            "names": ", ".join(getattr(report, 'names', 'No names found')),
            "Type": report.trid[0]["file_type"] if hasattr(report, 'trid') else "No filetype Found",
            "Type Probability": report.trid[0]["probability"] if hasattr(report, 'trid') else "No type probabilty"
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
        # Get the rows for the value and its report
        row_object = self.create_object(value_type, value, report)
        if report != NOT_FOUND_ERROR:
            try:
                row_object.pop("info")
            except Exception as e:
                print(e)
            
            # Construct rows from the value object
            rows = [[key, value] for key, value in row_object.items()]

            # Append standard rows
            standard_rows = [
                ["VirusTotal Total Votes", report.get("total_votes", 0)]
            ]
            rows.extend(standard_rows)

            return rows
        else:
            try:
                row_object.pop("info")
            except Exception as e:
                print(e)
            
            # Construct rows from the value object
            rows = [[key, value] for key, value in row_object.items()]
            
            # Append standard rows
            standard_rows = [
                ["VirusTotal Total Votes", NOT_FOUND_ERROR]
            ]
            rows.extend(standard_rows)
            
            return rows

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
        # Create a CSV report for the value
        csv_object = self.create_object(value_type, value, report)
        csv_report = [csv_object]

        return csv_report

    def get_report(self, value_type, value):
        """
        Get the report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value.
        """
        # Get the report for the value
        report = self.create_report(value_type, value)

        # Generate CSV report
        csv_report = self.csv_report(value_type, value, report)

        # Get rows for the report
        rows = self.get_rows(value_type, value, report)

        # Construct the final results dictionary
        results = {
            "report": report,
            "csv_report": csv_report,
            "rows": rows
        }

        return results