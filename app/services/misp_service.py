import datetime
import logging
import re
from typing import Dict, List, Optional

from pymisp import MISPObject

logger = logging.getLogger(__name__)

# object_name -> the CSV column that keys template lookups for that object type.
TEMPLATE_KEY_BY_OBJECT_NAME = {
    "file": "hash",
    "url": "url",
    "ip-port": "ip",
    "domain-ip": "domain",
}

# csv filename pattern -> MISP object name, checked in order.
FILENAME_PATTERNS = [
    (r"Hash", "file"),
    (r"URL", "url"),
    (r"IP", "ip-port"),
    (r"Domain", "domain-ip"),
]

# value_type (as used by the API's AnalyzeItem / HistoryService) -> MISP
# object name. Distinct from FILENAME_PATTERNS above: that regex-detects an
# object type from a CSV filename (CLI-only, via identify_object_type()).
# This maps directly from the type the API already knows - there's no
# filename to sniff in that flow.
OBJECT_NAME_BY_VALUE_TYPE = {
    "ips": "ip-port",
    "domains": "domain-ip",
    "urls": "url",
    "hashes": "file",
}

# object_name -> {report-field -> (misp_attribute_type, misp_type, category, to_ids)}.
# "general" isn't a real MISP object name - its entries (malicious_score, link)
# get merged into every other object type's mapping by callers, since every
# analyzed value has them regardless of type. Shared by both the CLI
# (app/MISP/vt_tools2misp.py's process_and_submit_to_misp) and the API's MISP
# push endpoint - one place owns this mapping, not two independently
# maintained copies. Moved here verbatim from where it used to be defined
# locally inside process_and_submit_to_misp.
ATTRIBUTE_TYPE_MAPPING = {
    "file": {
        "sha256": ("sha256", "sha256", "Payload delivery", False),
        "sha1": ("sha1", "sha1", "Payload delivery", False),
        "md5": ("md5", "md5", "Payload delivery", False),
        "ssdeep": ("ssdeep", "ssdeep", "Payload delivery", False),
        "tlsh": ("tlsh", "tlsh", "Payload delivery", False),
        "size": ("size", "size-in-bytes", "Payload delivery", False),
        "meaningful_name": ("filename", "text", "Payload delivery", False),
    },
    "domain-ip": {
        "domain": ("domain", "domain", "Network activity", False),
        "ip": ("ip", "ip-dst", "Network activity", False),
        "port": ("port", "port", "Network activity", False),
        "protocol": ("protocol", "text", "Network activity", False),
        "creation_date": ("creation_date", "datetime", "Network activity", False),
        "reputation": ("reputation", "text", "External analysis", False),
        "whois": ("whois", "text", "External analysis", False),
        "info": ("info", "text", "Other", False),
    },
    "url": {
        "url": ("url", "url", "Network activity", False),
        "domain": ("domain", "domain", "Network activity", False),
        "ip": ("ip", "ip-dst", "Network activity", False),
        "port": ("port", "port", "Network activity", False),
        "protocol": ("protocol", "text", "Network activity", False),
        "fragment": ("fragment", "text", "Other", False),
        "resource_path": ("resource_path", "text", "Network activity", False),
        "query_params": ("query_params", "text", "Other", False),
        "query_strings": ("query_strings", "text", "Other", False),
        "tld": ("tld", "text", "Other", False),
        "subdomain": ("subdomain", "text", "Other", False),
        "scheme": ("scheme", "text", "Other", False),
        "title": ("title", "text", "Other", False),
        "final_url": ("final_url", "url", "Network activity", False),
        "first_scan": ("first_scan", "datetime", "Other", False),
        "info": ("info", "text", "Other", False),
    },
    "ip-port": {
        "ip": ("ip", "ip-dst", "Network activity", False),
        "port": ("port", "port", "Network activity", False),
        "protocol": ("protocol", "text", "Network activity", False),
        "owner": ("owner", "text", "Other", False),
        "location": ("country-code", "text", "Network activity", False),
        "network": ("network", "text", "Other", False),
        "https_certificate": ("https_certificate", "text", "External analysis", False),
        "regional_internet_registry": ("regional_internet_registry", "text", "External analysis", False),
        "asn": ("AS", "AS", "Network activity", False),
    },
    "general": {
        "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
        "link": ("link", "link", "External analysis", False),
    },
}


class MispService:
    """Builds MISPObjects from already-analyzed CSV rows. No network calls, no
    interactive prompts - just data shaping, the MISP analog of
    VirusTotalService. The actual submission (needs a live ExpandedPyMISP
    connection) stays in app/MISP/vt_tools2misp.py."""

    def identify_object_type(self, csv_file: str) -> str:
        for pattern, misp_object_name in FILENAME_PATTERNS:
            if re.search(pattern, csv_file, re.IGNORECASE):
                return misp_object_name
        raise ValueError(f"Unknown CSV file format: '{csv_file}'. Could not determine MISP object name.")

    def build_attribute_mapping(self, headers: List[str], attribute_type_mapping: Dict[str, tuple]) -> Dict[str, tuple]:
        attribute_mapping = {}
        for header in headers:
            if header in attribute_type_mapping:
                attribute_mapping[header] = attribute_type_mapping[header]
            else:
                logger.warning(f"Header '{header}' not found in attribute_type_mapping.")
        if not attribute_mapping:
            raise ValueError("No valid attribute mappings were found based on the provided headers.")
        logger.info(f"Successfully mapped {len(attribute_mapping)} attributes.")
        return attribute_mapping

    def create_object(self, row: Dict[str, str], object_name: str, attribute_mapping: Dict[str, tuple]) -> Optional[MISPObject]:
        try:
            misp_object = MISPObject(name=object_name)
            misp_object.comment = row.get("comment", "")

            for key, value in row.items():
                if key not in attribute_mapping:
                    continue
                attr_details = attribute_mapping[key]
                if len(attr_details) != 4:
                    raise ValueError(f"Attribute mapping for '{key}' is incomplete (should contain 4 details).")
                attribute_type, attr_type, category, to_ids = attr_details

                if value in ["Not found", "Not Found", "", None, "null"]:
                    continue
                if attr_type == "datetime" and value == "0":
                    value = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                correlatable = attribute_type in ["ip", "url", "sha256", "md5", "sha1", "ssdeep", "tlsh"]
                misp_object.add_attribute(
                    attribute_type,
                    value=value,
                    type=attr_type,
                    category=category,
                    to_ids=correlatable,
                    disable_correlation=not correlatable,
                )
            return misp_object
        except Exception as e:
            logger.error(f"Failed to create MISP object from row: {row}. Error: {e}")
            return None

    def objects_from_csv(
        self,
        data: List[Dict[str, str]],
        object_name: str,
        attribute_mapping: Dict[str, tuple],
        template_object: Optional[Dict[str, Dict[str, List[str]]]] = None,
        template_key: Optional[str] = None,
    ) -> List[MISPObject]:
        if object_name not in TEMPLATE_KEY_BY_OBJECT_NAME:
            logger.error(f"Unsupported object name '{object_name}'.")
            return []

        if template_object and template_key:
            for row in data:
                key_value = row.get(template_key)
                if key_value and key_value in template_object:
                    for key, values in template_object[key_value].items():
                        row[key] = values[0] if len(values) == 1 else values

        misp_objects = []
        for row in data:
            misp_object = self.create_object(row, object_name, attribute_mapping)
            if misp_object:
                misp_objects.append(misp_object)

        if not misp_objects:
            logger.warning("No valid MISP objects were created.")
        return misp_objects
