import sqlite3
from sqlite3 import Error
from vt import url_id               # for interacting with urls in VirusTotal
from app.DataHandler.utils import utc2local  
IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = 'No https certificate found'
# Define the database schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    malicious_score TEXT,
    suspicious_score TEXT,
    safe_score TEXT,
    undetected_score TEXT,
    total_scans TEXT,
    link TEXT,
    title TEXT,
    final_url TEXT,
    first_scan TEXT,
    metadatas TEXT,
    targeted TEXT,
    links TEXT,
    redirection_chain TEXT,
    trackers TEXT
);

CREATE TABLE IF NOT EXISTS hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT,
    malicious_score TEXT,
    suspicious_score TEXT,
    safe_score TEXT,
    undetected_score TEXT,
    total_scans TEXT,
    link TEXT,
    extension TEXT,
    size TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    ssdeep TEXT,
    tlsh TEXT,
    names TEXT,
    type TEXT,
    type_probability TEXT
);

CREATE TABLE IF NOT EXISTS ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    malicious_score TEXT,
    suspicious_score TEXT,
    safe_score TEXT,
    undetected_score TEXT,
    total_scans TEXT,
    link TEXT,
    owner TEXT,
    location TEXT,
    network TEXT,
    https_certificate TEXT,
    regional_internet_registry TEXT,
    asn TEXT
);

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT,
    malicious_score TEXT,
    suspicious_score TEXT,
    safe_score TEXT,
    undetected_score TEXT,
    total_scans TEXT,
    link TEXT,
    creation_date TEXT,
    reputation TEXT,
    whois TEXT,
    last_analysis_results TEXT,
    last_analysis_stats TEXT,
    last_dns_records TEXT,
    last_https_certificate TEXT,
    registrar TEXT
);
"""
class DBHandler:
    def create_connection(self,db_file):
        """ create a database connection to a SQLite database """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            print(e)
        return conn

    def create_schema(self,conn):
        """ create tables in the SQLite database """
        try:
            c = conn.cursor()
            c.executescript(SCHEMA)
            print("Database schema created.")
        except Error as e:
            print(e)

    def insert_ip_data(self,conn, ip_data):
        """ Insert IP data into the ips table """
        sql = '''INSERT INTO ips(ip, malicious_score,suspicious_score,safe_score,undetected_score,total_scans,link,owner, location, network, https_certificate, regional_internet_registry, asn)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM ips WHERE ip=?", (ip_data.get("ip"),))
        result = cur.fetchone()
        if result:
            return
        
        cur.execute(sql, (
            ip_data.get("ip"),
            ip_data.get("malicious_score"),
            ip_data.get("suspicious_score"),
            ip_data.get("safe_score"),
            ip_data.get("undetected_score"),
            ip_data.get("total_scans"),
            ip_data.get("link"),
            ip_data.get("owner"),
            ip_data.get("location"),
            ip_data.get("network"),
            ip_data.get("https_certificate"),
            ip_data["info-ip"].get("regional_internet_registry"),
            ip_data["info-ip"].get("asn")
        ))
        conn.commit()

    def insert_domain_data(self,conn, domain_data):
        """ Insert domain data into the domains table """
        sql = '''INSERT INTO domains(domain,malicious_score,suspicious_score,safe_score,undetected_score,total_scans,link, creation_date, reputation, whois, last_analysis_results, last_analysis_stats, last_dns_records, last_https_certificate, registrar)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM domains WHERE domain=?", (domain_data.get("domain"),))
        result = cur.fetchone()
        if result:
            return
        
        cur.execute(sql, (
            domain_data.get("domain"),
            domain_data.get("malicious_score"),
            domain_data.get("suspicious_score"),
            domain_data.get("safe_score"),
            domain_data.get("undetected_score"),
            domain_data.get("total_scans"),
            domain_data.get("link"),
            domain_data.get("creation_date"),
            domain_data.get("reputation"),
            domain_data.get("whois"),
            str(domain_data["info"].get("last_analysis_results")),
            str(domain_data["info"].get("last_analysis_stats")),
            str(domain_data["info"].get("last_dns_records")),
            domain_data["info"].get("last_https_certificate"),
            domain_data["info"].get("registrar")
        ))
        conn.commit()

    def insert_url_data(self,conn, url_data):
        """ Insert URL data into the urls table """
        sql = '''INSERT INTO urls(url,malicious_score,suspicious_score,safe_score,undetected_score,total_scans,link,title, final_url, first_scan, metadatas, targeted, links, redirection_chain, trackers)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        cur = conn.cursor()
        
        cur.execute("SELECT * FROM urls WHERE url=?", (url_data.get("url"),))
        result = cur.fetchone()
        if result:
            return
        
        
        cur.execute(sql, (
            url_data.get("url"),
            url_data.get("malicious_score"),
            url_data.get("suspicious_score"),
            url_data.get("safe_score"),
            url_data.get("undetected_score"),
            url_data.get("total_scans"),
            url_data.get("link"),
            url_data.get("title"),
            url_data.get("final_Url"),
            url_data.get("first_scan"),
            str(url_data["info"].get("metadatas")),
            url_data["info"].get("targeted"),
            str(url_data["info"].get("links")),
            str(url_data["info"].get("redirection_chain")),
            str(url_data["info"].get("trackers"))
        ))
        conn.commit()

    def insert_hash_data(self,conn, hash_data):
        """ Insert hash data into the hashes table """
        sql = '''INSERT INTO hashes(hash,malicious_score,suspicious_score,safe_score,undetected_score,total_scans,link, extension, size, md5, sha1, sha256, ssdeep, tlsh, names, type, type_probability)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        cur = conn.cursor()
        
        # Check if the entry already exists in the database
        cur.execute("SELECT * FROM hashes WHERE hash=?", (hash_data.get("hash"),))
        result = cur.fetchone()
        if result:
            return
        
        cur.execute(sql, (
            hash_data.get("hash"),
            hash_data.get("malicious_score"),
            hash_data.get("suspicious_score"),
            hash_data.get("safe_score"),
            hash_data.get("undetected_score"),
            hash_data.get("total_scans"),
            hash_data.get("link"),
            hash_data.get("extension"),
            hash_data.get("size"),
            hash_data.get("md5"),
            hash_data.get("sha1"),
            hash_data.get("sha256"),
            hash_data.get("ssdeep"),
            hash_data.get("tlsh"),
            hash_data.get("names"),
            hash_data.get("Type"),
            hash_data.get("Type Probability")
        ))
        conn.commit()
        
    def ip_exists(self,ip, conn):
        """ Check if an IP exists in the database """
        cur = conn.cursor()
        cur.execute("SELECT * FROM ips WHERE ip=?", (ip,))
        result = cur.fetchone()
        return result

    def domain_exists(self,domain, conn):
        """ Check if a domain exists in the database """
        cur = conn.cursor()
        cur.execute("SELECT * FROM domains WHERE domain=?", (domain,))
        result = cur.fetchone()
        return result

    def url_exists(self,url, conn):
        """ Check if a URL exists in the database """
        cur = conn.cursor()
        cur.execute("SELECT * FROM urls WHERE url=?", (url,))
        result = cur.fetchone()
        return result

    def hash_exists(self,hash, conn):
        """ Check if a hash exists in the database """
        cur = conn.cursor()
        cur.execute("SELECT * FROM hashes WHERE hash=?", (hash,))
        result = cur.fetchone()
        return result

    def get_report(self,value, value_type, conn):

        """
        Get the report for a value.

        Parameters:
        value_type (str): The type of value.
        value (str): The value to get the report for.

        Returns:
        dict: The report for the value.
        """
        # Get the report for the value
        report = self.create_report(value_type, value, conn)
        if report:
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
        
    def create_report(self,value_type, value, conn):
        if conn is not None:
            if value_type == IPV4_PUBLIC_TYPE:
                report = conn.execute(f"SELECT * FROM ips WHERE ip = '{value}'").fetchone()
            elif value_type == "DOMAIN":
                report = conn.execute(f"SELECT * FROM domains WHERE domain = '{value}'").fetchone()
            elif value_type == "URL":
                report = conn.execute(f"SELECT * FROM urls WHERE url = '{value}'").fetchone()
            elif value_type == "SHA-256" or value_type == "SHA-1" or value_type == "MD5":
                report = conn.execute(f"SELECT * FROM hashes WHERE hash = '{value}'").fetchone()

            return report
        else:
            return None
        
    def csv_report(self,value_type, value, report):
        
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

    def create_object(self,value_type, value, report):
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "suspicious_score": NOT_FOUND_ERROR,
            "safe_score": NOT_FOUND_ERROR,
            "undetected_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "link": NO_LINK
        }
        
        if report != NOT_FOUND_ERROR and report:
            total_scans = report[6]
            malicious = report[2]
            suspicious = report[3]
            harmless = report[4]
            undetected = report[5]
            
            self.populate_scores(value_object, total_scans, malicious, suspicious, undetected, harmless)
            self.populate_link(value_object, value, value_type)

            if value_type == IPV4_PUBLIC_TYPE:
                self.populate_ip_data(value_object, value, report)
            elif value_type == "DOMAIN":
                self.populate_domain_data(value_object, value, report)
            elif value_type == "URL":
                self.populate_url_data(value_object, value, report)
            elif value_type == "SHA-256" or value_type == "SHA-1" or value_type == "MD5":
                self.populate_hash_data(value_object, value, report)

        return value_object

    def populate_scores(self,value_object, total_scans, malicious, suspicious, undetected, harmless):
        value_object["malicious_score"] = malicious
        value_object["suspicious_score"] = suspicious
        value_object["safe_score"] = harmless
        value_object["undetected_score"] = undetected
        value_object["total_scans"] = total_scans

    def populate_link(self,value_object, value, value_type):
        if value_type == "URL":
            value_object["link"] = f"https://www.virustotal.com/gui/url/{url_id(value)}"
        else:
            value_object["link"] = f"https://www.virustotal.com/gui/search/{value}"
            
    def populate_ip_data(self,value_object, value, report):
        value_object.update({
            "ip": value,
            "owner": report[8],
            "location": report[9],
            "network": report[10],
            "https_certificate": report[11],
            "info-ip": {
                "regional_internet_registry": report[12],
                "asn": report[13]
            }
        })

    def populate_domain_data(self,value_object, value, report):
        value_object.update({
            "domain": value,
            "creation_date":report[8],
            "reputation": report[9],
            "whois": report[10],
            "info": {
                "last_analysis_results": report[11],
                "last_analysis_stats": report[12],
                "last_dns_records": report[13],
                "last_https_certificate": report[14],
                "registrar": report[15]
            }
        })

    def populate_url_data(self,value_object, value, report):
        value_object.update({
            "url": value,
            "title": report[8],
            "final_url": report[9],
            "first_scan": report[10],
            "info": {
                "metadatas": report[11],
                "targeted": report[12],
                "links": report[13],
                "redirection_chain": report[14],
                "trackers": report[15]
            }
        })

    def populate_hash_data(self,value_object, value, report):
        value_object.update({
            "hash": value,
            "extension": report[8],
            "size": report[9],
            "md5": report[10],
            "sha1": report[11],
            "sha256": report[12],
            "ssdeep": report[13],
            "tlsh": report[14],
            "names": report[15],
            "type": report[16],
            "type_probability": report[17]
        })

    def get_rows(self,value_type, value, report):
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
                pass
            
            # Construct rows from the value object
            rows = [[key, value] for key, value in row_object.items()]

            return rows

