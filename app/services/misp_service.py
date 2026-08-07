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
