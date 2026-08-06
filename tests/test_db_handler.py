import unittest

from app.DBHandler.db_handler import DBHandler


IP_ROW = {
    "ip": "8.8.8.8",
    "port": "Not found",
    "protocol": "Not found",
    "malicious_score": "0",
    "total_scans": "10",
    "tags": "Not found",
    "link": "l",
    "owner": "Google",
    "location": "US",
    "network": "8.8.8.0/24",
    "https_certificate": "Not found",
    "info-ip": {"regional_internet_registry": "ARIN", "asn": "15169"},
}


class SchemaAndConnectionTests(unittest.TestCase):
    def test_create_schema_creates_all_tables(self):
        db = DBHandler()
        conn = db.create_connection(":memory:")
        db.create_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        # sqlite_sequence is an internal bookkeeping table SQLite creates
        # automatically because the schema uses AUTOINCREMENT columns.
        tables.discard("sqlite_sequence")
        self.assertEqual(tables, {"urls", "hashes", "ips", "domains"})


class InsertAndUpsertTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_insert_ip_data_creates_one_row(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ips")
        self.assertEqual(cur.fetchone()[0], 1)

    def test_reinsert_same_key_updates_instead_of_duplicating(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        updated = dict(IP_ROW, malicious_score="5")
        self.db.insert_ip_data(self.conn, updated)

        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM ips")
        self.assertEqual(cur.fetchone()[0], 1)
        cur.execute("SELECT malicious_score FROM ips WHERE ip = ?", ("8.8.8.8",))
        self.assertEqual(cur.fetchone()[0], "5")


class ExistsTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_false_when_absent(self):
        self.assertFalse(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))

    def test_true_when_present(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        self.assertTrue(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))

    def test_mostly_not_found_row_reads_as_not_existing(self):
        # A row where >=80% of its non-key columns are the NOT_FOUND_ERROR
        # sentinel ("Not found") should be treated as a cache miss, so a
        # value that previously came back empty gets retried instead of
        # being served from a useless cached row forever.
        empty_row = dict(IP_ROW)
        for key in ("port", "protocol", "malicious_score", "total_scans",
                    "tags", "link", "owner", "location", "network",
                    "https_certificate"):
            empty_row[key] = "Not found"
        empty_row["info-ip"] = {"regional_internet_registry": "Not found", "asn": "Not found"}
        self.db.insert_ip_data(self.conn, empty_row)
        self.assertFalse(self.db.exists(self.conn, "ips", "8.8.8.8", "ip"))


class GetReportRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.db = DBHandler()
        self.conn = self.db.create_connection(":memory:")
        self.db.create_schema(self.conn)

    def test_hash_report_fields_are_correctly_positioned(self):
        # The hashes table schema happens to put malicious_score/total_scans/
        # tags exactly where populate_scores/populate_tags read them, so this
        # path is correct.
        hash_row = {
            "hash": "a" * 64, "malicious_score": "7", "total_scans": "70",
            "tags": "trojan", "threat_category": "tc", "threat_labels": "tl",
            "link": "l", "extension": "exe", "size": "123", "md5": "m",
            "sha1": "s1", "sha256": "s2", "ssdeep": "sd", "tlsh": "t",
            "meaningful_name": "n", "names": "names", "type": "PE",
            "type_probability": "0.9",
        }
        self.db.insert_hash_data(self.conn, hash_row)
        report = self.db.get_report(hash_row["hash"], "SHA-256", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "7")
        self.assertEqual(csv_row["tags"], "trojan")

    def test_domain_report_score_and_tag_fields_are_correct(self):
        domain_row = {
            "domain": "example.com", "ip": "1.2.3.4", "port": "443",
            "protocol": "https", "malicious_score": "9", "total_scans": "90",
            "tags": "phishing", "link": "l", "creation_date": "2020",
            "reputation": "0", "whois": "w",
            "info": {
                "last_analysis_results": "x", "last_analysis_stats": "y",
                "last_dns_records": "z", "last_https_certificate": "c",
                "registrar": "r",
            },
        }
        self.db.insert_domain_data(self.conn, domain_row)
        report = self.db.get_report("example.com", "DOMAIN", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "9")
        self.assertEqual(csv_row["total_scans"], "90")
        self.assertEqual(csv_row["tags"], "phishing")

    def test_ip_report_score_and_tag_fields_are_correct(self):
        self.db.insert_ip_data(self.conn, IP_ROW)
        report = self.db.get_report("8.8.8.8", "PUBLIC IPV4", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "0")
        self.assertEqual(csv_row["total_scans"], "10")
        self.assertEqual(csv_row["tags"], "Not found")

    def test_url_report_score_and_tag_fields_are_correct(self):
        # populate_url_data() also sets malicious_score/total_scans/tags
        # with its own (correct) indices, redundantly re-confirming what
        # populate_scores()/populate_tags() already set.
        url_row = {
            "url": "http://x.com/a", "domain": "x.com", "ip": "1.1.1.1",
            "port": "80", "protocol": "http", "fragment": "",
            "resource_path": "/a", "query_params": "", "query_strings": "",
            "tld": "com", "subdomain": "", "scheme": "http",
            "malicious_score": "3", "total_scans": "30", "tags": "malware",
            "link": "l", "title": "t", "final_url": "f", "first_scan": "fs",
            "metadatas": "m", "targeted": "tg", "links": "lk",
            "redirection_chain": "rc", "trackers": "tr",
        }
        self.db.insert_url_data(self.conn, url_row)
        report = self.db.get_report("http://x.com/a", "URL", self.conn)
        csv_row = report["csv_report"][0]
        self.assertEqual(csv_row["malicious_score"], "3")
        self.assertEqual(csv_row["tags"], "malware")

    def test_get_report_returns_none_for_missing_value(self):
        self.assertIsNone(self.db.get_report("nope.example", "DOMAIN", self.conn))


if __name__ == "__main__":
    unittest.main()
