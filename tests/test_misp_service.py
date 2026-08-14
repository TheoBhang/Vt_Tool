import unittest

from app.services.misp_service import MispService


class MispServiceTests(unittest.TestCase):
    def test_identify_object_type_matches_known_patterns(self):
        service = MispService()
        self.assertEqual(service.identify_object_type("000001_Hashes_Analysis_x.csv"), "file")
        self.assertEqual(service.identify_object_type("000001_URL_Analysis_x.csv"), "url")
        self.assertEqual(service.identify_object_type("000001_IP_Analysis_x.csv"), "ip-port")
        self.assertEqual(service.identify_object_type("000001_Domains_Analysis_x.csv"), "domain-ip")
        self.assertEqual(service.identify_object_type("000001_hashes_analysis_x.csv"), "file")

    def test_identify_object_type_unknown_filename_raises(self):
        service = MispService()
        with self.assertRaises(ValueError):
            service.identify_object_type("unrelated_file.csv")

    def test_build_attribute_mapping_maps_known_headers(self):
        service = MispService()
        mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        result = service.build_attribute_mapping(["ip", "malicious_score"], mapping)
        self.assertEqual(result, {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_build_attribute_mapping_raises_when_nothing_matches(self):
        service = MispService()
        with self.assertRaises(ValueError):
            service.build_attribute_mapping(["nope"], {"ip": ("ip", "ip-dst", "Network activity", False)})

    def test_create_object_builds_misp_object_with_mapped_attributes(self):
        service = MispService()
        row = {"ip": "8.8.8.8", "malicious_score": "Not found", "comment": "hi"}
        attribute_mapping = {
            "ip": ("ip", "ip-dst", "Network activity", False),
            "malicious_score": ("malicious_score", "text", "Antivirus detection", False),
        }
        obj = service.create_object(row, "ip-port", attribute_mapping)
        self.assertEqual(obj.name, "ip-port")
        self.assertEqual(obj.comment, "hi")
        self.assertEqual(len(obj.attributes), 1)
        self.assertEqual(obj.attributes[0].type, "ip-dst")
        self.assertEqual(obj.attributes[0].value, "8.8.8.8")

    def test_create_object_incomplete_mapping_returns_none(self):
        service = MispService()
        row = {"ip": "8.8.8.8"}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity")}  # missing 4th element
        self.assertIsNone(service.create_object(row, "ip-port", attribute_mapping))

    def test_objects_from_csv_applies_template_and_builds_objects(self):
        service = MispService()
        data = [{"ip": "8.8.8.8", "malicious_score": "0"}]
        template_object = {"8.8.8.8": {"comment": ["from template"]}}
        attribute_mapping = {"ip": ("ip", "ip-dst", "Network activity", False)}
        objects = service.objects_from_csv(
            data, "ip-port", attribute_mapping, template_object=template_object, template_key="ip"
        )
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0].comment, "from template")

    def test_objects_from_csv_unsupported_object_name_returns_empty(self):
        service = MispService()
        objects = service.objects_from_csv([{"a": "b"}], "bogus-type", {})
        self.assertEqual(objects, [])

    def test_object_name_by_value_type_covers_all_four_types(self):
        from app.services.misp_service import OBJECT_NAME_BY_VALUE_TYPE
        self.assertEqual(OBJECT_NAME_BY_VALUE_TYPE, {
            "ips": "ip-port",
            "domains": "domain-ip",
            "urls": "url",
            "hashes": "file",
        })

    def test_attribute_type_mapping_covers_every_object_name_plus_general(self):
        from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING, OBJECT_NAME_BY_VALUE_TYPE
        for object_name in OBJECT_NAME_BY_VALUE_TYPE.values():
            self.assertIn(object_name, ATTRIBUTE_TYPE_MAPPING)
        self.assertIn("general", ATTRIBUTE_TYPE_MAPPING)
        self.assertIn("malicious_score", ATTRIBUTE_TYPE_MAPPING["general"])
        self.assertIn("link", ATTRIBUTE_TYPE_MAPPING["general"])

    def test_attribute_type_mapping_file_entry_matches_hash_report_fields(self):
        from app.services.misp_service import ATTRIBUTE_TYPE_MAPPING
        file_mapping = ATTRIBUTE_TYPE_MAPPING["file"]
        self.assertEqual(file_mapping["sha256"], ("sha256", "sha256", "Payload delivery", False))
        self.assertEqual(file_mapping["meaningful_name"], ("filename", "text", "Payload delivery", False))


if __name__ == "__main__":
    unittest.main()
