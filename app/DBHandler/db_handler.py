import sqlite3
from sqlite3 import Error

from vt import url_id  # for interacting with urls in VirusTotal

IPV4_PUBLIC_TYPE = "PUBLIC IPV4"
NOT_FOUND_ERROR = "Not found"
NO_LINK = "No link"
NO_HTTP_CERT = "No https certificate found"

SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    malicious_score TEXT,
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
    def create_connection(self, db_file):
        """Create a database connection to a SQLite database"""
        conn = None
        try:
            conn = sqlite3.connect(db_file)
        except Error as e:
            print(f"Error connecting to SQLite database: {e}")
        return conn

    def create_schema(self, conn):
        """Create tables in the SQLite database"""
        try:
            c = conn.cursor()
            c.executescript(SCHEMA)
            print("Database schema created.")
        except Error as e:
            print(f"Error creating schema: {e}")

    def close_connection(self, conn):
        """Close the database connection"""
        if conn:
            conn.close()
            print("SQLite database connection closed.")

    def insert_ip_data(self, conn, ip_data):
        """Insert IP data into the ips table"""
        sql = """INSERT INTO ips(ip, malicious_score, 
                total_scans, link, owner, location, network, https_certificate,
                regional_internet_registry, asn)
                VALUES(?,?,?,?,?,?,?,?,?,?)"""

        try:
            cur = conn.cursor()

            # Check if the entry already exists in the database
            cur.execute("SELECT * FROM ips WHERE ip=?", (ip_data.get("ip"),))
            result = cur.fetchone()
            if result:
                return

            # Insert new IP data
            cur.execute(
                sql,
                (
                    str(ip_data.get("ip")),
                    str(ip_data.get("malicious_score")),
                    str(ip_data.get("total_scans")),
                    str(ip_data.get("link")),
                    str(ip_data.get("owner")),
                    str(ip_data.get("location")),
                    str(ip_data.get("network")),
                    str(ip_data.get("https_certificate")),
                    str(ip_data["info-ip"].get("regional_internet_registry")),
                    str(ip_data["info-ip"].get("asn")),
                ),
            )

            conn.commit()  # Commit transaction
        except Exception as e:
            conn.rollback()  # Rollback transaction on error
            print(f"Error inserting IP data: {e}")
        finally:
            cur.close()  # Close cursor


    def insert_domain_data(self, conn, domain_data):
        """Insert domain data into the domains table"""
        sql = """INSERT INTO domains(domain, malicious_score,
                total_scans, link, creation_date, reputation, whois, last_analysis_results, last_analysis_stats,
                last_dns_records, last_https_certificate, registrar)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"""

        try:
            cur = conn.cursor()

            # Check if the entry already exists in the database
            cur.execute("SELECT * FROM domains WHERE domain=?", (domain_data.get("domain"),))
            result = cur.fetchone()
            if result:
                return

            # Insert new domain data
            cur.execute(
                sql,
                (
                    domain_data.get("domain"),
                    domain_data.get("malicious_score"),
                    domain_data.get("total_scans"),
                    domain_data.get("link"),
                    domain_data.get("creation_date"),
                    domain_data.get("reputation"),
                    domain_data.get("whois"),
                    str(domain_data["info"].get("last_analysis_results")),
                    str(domain_data["info"].get("last_analysis_stats")),
                    str(domain_data["info"].get("last_dns_records")),
                    domain_data["info"].get("last_https_certificate"),
                    domain_data["info"].get("registrar"),
                ),
            )

            conn.commit()  # Commit transaction
        except Exception as e:
            conn.rollback()  # Rollback transaction on error
            print(f"Error inserting domain data: {e}")
        finally:
            cur.close()  # Close cursor
        
    def insert_url_data(self, conn, url_data):
        """Insert URL data into the urls table"""
        sql = """INSERT INTO urls(url, malicious_score, 
                    total_scans, link, title, final_url, first_scan, metadatas, targeted, links, redirection_chain, trackers)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"""

        try:
            cur = conn.cursor()

            # Check if the entry already exists in the database
            cur.execute("SELECT * FROM urls WHERE url=?", (url_data.get("url"),))
            result = cur.fetchone()
            if result:
                return

            # Insert new URL data
            cur.execute(
                sql,
                (
                    url_data.get("url"),
                    url_data.get("malicious_score"),
                    url_data.get("total_scans"),
                    url_data.get("link"),
                    url_data.get("title"),
                    url_data.get("final_url"),
                    url_data.get("first_scan"),
                    str(url_data["info"].get("metadatas")),
                    url_data["info"].get("targeted"),
                    str(url_data["info"].get("links")),
                    str(url_data["info"].get("redirection_chain")),
                    str(url_data["info"].get("trackers")),
                ),
            )

            conn.commit()  # Commit transaction
        except Exception as e:
            conn.rollback()  # Rollback transaction on error
            print(f"Error inserting URL data: {e}")
        finally:
            cur.close()  # Close cursor

    def insert_hash_data(self, conn, hash_data):
        """Insert hash data into the hashes table"""
        sql = """INSERT INTO hashes(hash, malicious_score, 
                total_scans, link, extension, size, md5, sha1, sha256, ssdeep, tlsh, names, type, type_probability)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
        try:
            cur = conn.cursor()

            # Check if the entry already exists in the database
            cur.execute("SELECT * FROM hashes WHERE hash=? OR md5=? OR sha1=?", (hash_data.get("hash"), hash_data.get("hash"), hash_data.get("hash")))
            result = cur.fetchone()
            if result:
                return

            # Insert new hash data
            cur.execute(
                sql,
                (
                    hash_data.get("hash"),
                    hash_data.get("malicious_score"),
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
                    hash_data.get("type"),
                    hash_data.get("type_probability"),
                ),
            )

            conn.commit()  # Commit transaction
        except Exception as e:
            conn.rollback()  # Rollback transaction on error
            print(f"Error inserting hash data: {e}")
        finally:
            cur.close()  # Close cursor

    def ip_exists(self, ip, conn):
        """Check if an IP exists in the database"""
        query = "SELECT * FROM ips WHERE ip = ?"
        
        try:
            cur = conn.cursor()
            cur.execute(query, (ip,))   
            result = cur.fetchone()
            cur.close()  # Close the cursor after use
            return result if result else None
        except Exception as e:
            # Handle exception (logging, re-raising, etc.)
            print(f"An error occurred: {e}")
            return None

    def domain_exists(self, domain, conn):
        """Check if a domain exists in the database"""
        query = "SELECT * FROM domains WHERE domain = ?"
        
        try:
            cur = conn.cursor()
            cur.execute(query, (domain,))
            result = cur.fetchone()
            cur.close()  # Close the cursor after use
            return result if result else None
        except Exception as e:
            # Handle exception (logging, re-raising, etc.)
            print(f"An error occurred: {e}")
            return None

    def url_exists(self, url, conn):
        """Check if a URL exists in the database"""
        query = "SELECT * FROM urls WHERE url = ?"
        
        try:
            cur = conn.cursor()
            cur.execute(query, (url,))
            result = cur.fetchone()
            cur.close()  # Close the cursor after use
            return result if result else None
        except Exception as e:
            # Handle exception (logging, re-raising, etc.)
            print(f"An error occurred: {e}")
            return None

    def hash_exists(self, hash, conn):
        """Check if a hash exists in the database"""
        query = """
        SELECT * FROM hashes 
        WHERE hash = ? OR md5 = ? OR sha1 = ?
        """
        
        try:
            cur = conn.cursor()
            cur.execute(query, (hash, hash, hash))
            result = cur.fetchone()
            cur.close()  # Close the cursor after use
            return result if result else None
        except Exception as e:
            # Handle exception (logging, re-raising, etc.)
            print(f"An error occurred: {e}")
            return None

    def get_report(self, value, value_type, conn):
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
            results = {"report": report, "csv_report": csv_report, "rows": rows}

            return results

    def create_report(self, value_type, value, conn):
        """Fetch a report from the database based on value_type and value"""
        if conn is None:
            return None

        cursor = conn.cursor()
        report = None

        try:
            if value_type == IPV4_PUBLIC_TYPE:
                cursor.execute("SELECT * FROM ips WHERE ip = ?", (value,))
            elif value_type == "DOMAIN":
                cursor.execute("SELECT * FROM domains WHERE domain = ?", (value,))
            elif value_type == "URL":
                cursor.execute("SELECT * FROM urls WHERE url = ?", (value,))
            elif value_type in ["SHA-256", "SHA-1", "MD5"]:
                cursor.execute("SELECT * FROM hashes WHERE hash = ? OR md5 = ? OR sha1 = ?", (value,value,value))

            report = cursor.fetchone()
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            cursor.close()

        return report

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

    def create_object(self, value_type, value, report):
        value_object = {
            "malicious_score": NOT_FOUND_ERROR,
            "total_scans": NOT_FOUND_ERROR,
            "link": NO_LINK,
        }

        if report != NOT_FOUND_ERROR and report:
            total_scans = report[3]
            malicious = report[2]

            self.populate_scores(
                value_object, total_scans, malicious
            )
            self.populate_link(value_object, value, value_type)

            if value_type == IPV4_PUBLIC_TYPE:
                self.populate_ip_data(value_object, value, report)
            elif value_type == "DOMAIN":
                self.populate_domain_data(value_object, value, report)
            elif value_type == "URL":
                self.populate_url_data(value_object, value, report)
            elif (
                value_type == "SHA-256" or value_type == "SHA-1" or value_type == "MD5"
            ):
                self.populate_hash_data(value_object, value, report)

        return value_object

    def populate_scores(
        self, value_object, total_scans, malicious
    ):
        value_object["malicious_score"] = malicious
        value_object["total_scans"] = total_scans

    def populate_link(self, value_object, value, value_type):
        if value_type == "URL":
            value_object["link"] = f"https://www.virustotal.com/gui/url/{url_id(value)}"
        else:
            value_object["link"] = f"https://www.virustotal.com/gui/search/{value}"

    def populate_ip_data(self, value_object, value, report):
        """
        Populate IP-related data into the given value_object based on the report.

        Parameters:
        - value_object (dict): The dictionary to populate with IP data.
        - value (str): The IP address.
        - report (tuple or list): A tuple or list containing IP-related information.

        Note:
        - Assumes report structure: (owner, location, network, https_certificate,
        regional_internet_registry, asn)
        """
        value_object.update({
            "ip": value,
            "owner": report[5],
            "location": report[6],
            "network": report[7],
            "https_certificate": report[8],
            "info-ip": {
                "regional_internet_registry": report[9],
                "asn": report[10],
            },
        })

    def populate_domain_data(self, value_object, value, report):
        """
        Populate domain-related data into the given value_object based on the report.

        Parameters:
        - value_object (dict): The dictionary to populate with domain data.
        - value (str): The domain name.
        - report (tuple or list): A tuple or list containing domain-related information.

        Note:
        - Assumes report structure: (creation_date, reputation, whois,
        last_analysis_results, last_analysis_stats, last_dns_records,
        last_https_certificate, registrar)
        """
        value_object.update({
            "domain": value,
            "creation_date": report[5],
            "reputation": report[6],
            "whois": report[7],
            "info": {
                "last_analysis_results": report[8],
                "last_analysis_stats": report[9],
                "last_dns_records": report[10],
                "last_https_certificate": report[11],
                "registrar": report[12],
            },
        })

    def populate_url_data(self, value_object, value, report):
        """
        Populate URL-related data into the given value_object based on the report.

        Parameters:
        - value_object (dict): The dictionary to populate with URL data.
        - value (str): The URL.
        - report (tuple or list): A tuple or list containing URL-related information.

        Note:
        - Assumes report structure: (title, final_url, first_scan,
        metadatas, targeted, links, redirection_chain, trackers)
        """
        value_object.update({
            "url": value,
            "title": report[5],
            "final_url": report[6],
            "first_scan": report[7],
            "info": {
                "metadatas": report[8],
                "targeted": report[9],
                "links": report[10],
                "redirection_chain": report[11],
                "trackers": report[12],
            },
        })

    def populate_hash_data(self, value_object, value, report):
        """
        Populate hash-related data into the given value_object based on the report.
        
        Parameters:
        - value_object (dict): The dictionary to populate with hash data.
        - value (str): The hash value.
        - report (tuple or list): A tuple or list containing hash-related information.
        
        Note:
        - Assumes report structure: (extension, size, md5, sha1, sha256, ssdeep, tlsh, 
        names, type, type_probability)
        """
        value_object.update(
            {
                "hash": value,
                "extension": report[5],
                "size": report[6],
                "md5": report[7],
                "sha1": report[8],
                "sha256": report[9],
                "ssdeep": report[10],
                "tlsh": report[11],
                "names": report[12],
                "type": report[13],
                "type_probability": report[14],
            }
            
        )

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
                pass
            # Construct rows from the value object
            rows = [[key, value] for key, value in row_object.items()]
            # Append standard rows
            standard_rows = [["VirusTotal Total Votes", getattr(report, "total_votes", "No total votes found")]]
            rows.extend(standard_rows)
            
            return rows
