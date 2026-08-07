import logging

from vt import url_id

from app.DataHandler.utils import utc2local, build_virustotal_link
from app.DataHandler.validator import (
    get_service_name,
    get_url_details,
    extract_ip_address,
    get_port_from_service_name,
)
from app.errors import VirusTotalAPIError

IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"

logger = logging.getLogger(__name__)


class VirusTotalService:
    """Fetches a VirusTotal report and shapes it into vt_tool's flat report dict.
    This is the only place report-shaping happens - the cache stores whatever
    this returns verbatim and never re-derives it."""

    def __init__(self, vt_client):
        self.vt = vt_client

    def get_report(self, value_type: str, value) -> dict:
        report = self._fetch(value_type, value)
        value_object = self._initialize(value_type)
        self._populate(value_object, value_type, value, report)
        return value_object

    def _fetch(self, value_type, value):
        if isinstance(value, tuple):
            value = value[0]
        api_endpoints = {
            IPV4_PUBLIC_TYPE: f"/ip_addresses/{value}",
            "DOMAIN": f"/domains/{value}",
            "URL": f"/urls/{url_id(value)}",
            "SHA-256": f"/files/{value}",
            "SHA-1": f"/files/{value}",
            "MD5": f"/files/{value}",
        }
        if value_type not in api_endpoints:
            raise VirusTotalAPIError(f"No VirusTotal endpoint for value type: {value_type}")
        try:
            return self.vt.get_object(api_endpoints[value_type])
        except Exception as e:
            if "NotFoundError" in str(e):
                logger.warning(f"{NOT_FOUND_ERROR} on VirusTotal Database: {value}")
                return None
            logger.error(f"Error fetching report for {value_type}: {value} - {e}")
            raise VirusTotalAPIError(str(e)) from e

    def _initialize(self, value_type):
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "tags": NOT_FOUND_ERROR,
            "link": NOT_FOUND_ERROR,
        }
        if value_type in ["SHA-256", "SHA-1", "MD5"]:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR
        return value_object

    def _populate(self, value_object, value_type, value, report):
        if report is None:
            total_scans = 0
            malicious = 0
        else:
            total_scans = sum(report.last_analysis_stats.values())
            malicious = report.last_analysis_stats.get("malicious", 0)
        value_object["malicious_score"] = malicious
        value_object["total_scans"] = total_scans
        value_object["link"] = build_virustotal_link(value, value_type)
        tags = getattr(report, "tags", [])
        value_object["tags"] = ", ".join(tags) if tags else NOT_FOUND_ERROR

        if value_type == IPV4_PUBLIC_TYPE:
            self._populate_ip(value_object, value, report)
        elif value_type == "DOMAIN":
            self._populate_domain(value_object, value, report)
        elif value_type == "URL":
            self._populate_url(value_object, value, report)
        elif value_type in ["SHA-256", "SHA-1", "MD5"]:
            self._populate_hash(value_object, value, report)
            self._populate_threat_classification(value_object, report)

    def _populate_ip(self, value_object, value, report):
        if isinstance(value, tuple):
            ip, port = value
        else:
            ip, port = value, None
        value_object.update({
            "ip": ip,
            "port": port if port else NOT_FOUND_ERROR,
            "protocol": get_service_name(port) if port else NOT_FOUND_ERROR,
            "owner": getattr(report, "as_owner", NOT_FOUND_ERROR),
            "location": f"{report.continent} / {report.country}"
                if hasattr(report, "continent") and hasattr(report, "country")
                else NOT_FOUND_ERROR,
            "network": getattr(report, "network", NOT_FOUND_ERROR),
            "https_certificate": getattr(report, "last_https_certificate", NOT_FOUND_ERROR),
            "info-ip": {
                "regional_internet_registry": getattr(report, "regional_internet_registry", NOT_FOUND_ERROR),
                "asn": getattr(report, "asn", NOT_FOUND_ERROR),
            },
        })

    def _populate_domain(self, value_object, value, report):
        ip = getattr(report, "whois", {})
        if isinstance(ip, str):
            ip = extract_ip_address(ip)
        value_object.update({
            "domain": value,
            "ip": ip if ip else NOT_FOUND_ERROR,
            "port": getattr(report, "port", NOT_FOUND_ERROR),
            "protocol": get_service_name(getattr(report, "port", None))
                if getattr(report, "port", None) else NOT_FOUND_ERROR,
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

    def _populate_url(self, value_object, value, report):
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

        port = details["port"] if details["port"] else get_port_from_service_name(details["scheme"])

        value_object.update({
            "url": value,
            "domain": details["domain"] if details["domain"] != '' else NOT_FOUND_ERROR,
            "ip": getattr(report, "ip_address", NOT_FOUND_ERROR),
            "port": port,
            "protocol": get_service_name(details["port"]) if details["port"] != '' else NOT_FOUND_ERROR,
            "fragment": details["fragment"] if details["fragment"] != '' else NOT_FOUND_ERROR,
            "resource_path": details["resource_path"] if details["resource_path"] != '' else NOT_FOUND_ERROR,
            "query_params": details["query_params"] if details["query_params"] != '' else NOT_FOUND_ERROR,
            "query_strings": details["query_strings"] if details["query_strings"] != '' else NOT_FOUND_ERROR,
            "tld": details["tld"] if details["tld"] != '' else NOT_FOUND_ERROR,
            "subdomain": details["subdomain"] if details["subdomain"] != '' else NOT_FOUND_ERROR,
            "scheme": details["scheme"] if details["scheme"] != '' else NOT_FOUND_ERROR,
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

    def _populate_hash(self, value_object, value, report):
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

    def _populate_threat_classification(self, value_object, report):
        try:
            if report.popular_threat_classification:
                classification = report.get("popular_threat_classification", {})
                categories = classification.get('popular_threat_category', [])
                value_object["threat_category"] = ", ".join(c['value'] for c in categories)
                value_object["threat_labels"] = classification.get("suggested_threat_label", NOT_FOUND_ERROR)
            else:
                value_object["threat_category"] = NOT_FOUND_ERROR
                value_object["threat_labels"] = NOT_FOUND_ERROR
        except Exception:
            value_object["threat_category"] = NOT_FOUND_ERROR
            value_object["threat_labels"] = NOT_FOUND_ERROR
