#encoding: utf-8
"""
 Fetches data from VT based on multiple values such as Hash, Ip, Domain or Urls
 and adds the data into two files for each categories of Objects
 - CSV File containing the data
 - TXT File containing the table with more readable datas
---
MIT License

Copyright (c) 2023 Theo Bhang (THA-CERT https://github.com/thalesgroup-cert)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse                     # for parsing command line arguments
from cortexutils.analyzer import Analyzer
import logging                      # for logging
import time                         # for sleeping
from app.init import Initializator # for initializing the script
from app.FileHandler.read_file import ValueReader # for reading values from a file
from app.DataHandler.utils import get_api_key, get_proxy, get_user_choice # for interacting with the operating system
        

class VTToolAnalyzer(Analyzer):
    """
    A class for analyzing values using VirusTotal.

    Attributes:
    api_key (str): The VirusTotal API key.
    proxy (str): The proxy to use for requests.
    client (vt.Client): The VirusTotal client.
    reporter (VirusTotalReporter): The VirusTotal reporter.
    validator (DataValidator): The data validator.
    output (OutputHandler): The output handler.

    """
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.virustotal_key = self.get_param(
            "config.key", None, "Missing VirusTotal API key"
        )
        self.proxies = self.get_param("config.proxy.https", None)
        self.case_id = self.get_param("config.case_id", None)
        
        self.file_path = self.get_param("file", None, "File is missing")
        self.threshold = self.get_param("config.threshold", None, "Threshold is missing")

    def artifacts(self, raw):
        artifacts = []
        for ioc_type in raw.get("iocs", []):
            for ioc in raw.get("iocs").get(ioc_type):
                artifacts.append(self.build_artifact(ioc_type, ioc.get("data"), tags=["malicious_score:{}".format(ioc.get("malicious_score"))]))
        return artifacts

    def summary(self, raw):
        """
        Returns a short summary.

        Parameters:
        raw (dict): The raw JSON report.

        Returns:
        str: The short summary.
        """
        taxonomies = []
        namespace = "VT_Tool"
        predicate = "Analysis"
        logging.warning(f"Raw: {raw}")
        if self.service == "ips":
            predicate = "IP_Analysis"
            logging.warning(f"Threshold: {self.threshold}")

            for ip in raw["iocs"]["ips"]:
                try:
                    if int(ip["safe_score"]) >= self.threshold:
                        level = "safe"
                    elif int(ip["suspicious_score"]) >= self.threshold:
                        level = "suspicious"
                    elif int(ip["malicious_score"]) >= self.threshold:
                        level = "malicious"
                    else:
                        level = "info"
                except Exception as e:
                    level = "info"
                try:
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, ip["data"])
                    )
                except Exception as e:
                    logging.warning(f"Error building taxonomy for {ip}: {e}")
        elif self.service == "domains":
            predicate = "Domain_Analysis"
            for domain in raw["iocs"]["domains"]:
                try:
                    if int(domain["safe_score"]) >= self.threshold:
                        level = "safe"
                    elif int(domain["suspicious_score"]) >= self.threshold:
                        level = "suspicious"
                    elif int(domain["malicious_score"]) >= self.threshold:
                        level = "malicious"
                    else:
                        level = "info"
                except Exception as e:
                    level = "info"
                try:
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, domain["data"])
                    )
                except Exception as e:
                    logging.warning(f"Error building taxonomy for {domain}: {e}")
        elif self.service == "urls":
            predicate = "URL_Analysis"
            for url in raw["iocs"]["urls"]:
                try:
                    if int(url["safe_score"]) >= self.threshold:
                        level = "safe"
                    elif int(url["suspicious_score"]) >= self.threshold:
                        level = "suspicious"
                    elif int(url["malicious_score"]) >= self.threshold:
                        level = "malicious"
                    else:
                        level = "info"
                except Exception as e:
                    level = "info"
                try:
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, url["data"])
                    )
                except Exception as e:
                    logging.warning(f"Error building taxonomy for {url}: {e}")
        elif self.service == "hashes":
            predicate = "Hash_Analysis"
            for hash in raw["iocs"]["hashes"]:
                try:
                    if int(hash["safe_score"]) >= self.threshold:
                        level = "safe"
                    elif int(hash["suspicious_score"]) >= self.threshold:
                        level = "suspicious"
                    elif int(hash["malicious_score"]) >= self.threshold:
                        level = "malicious"
                    else:
                        level = "info"
                except Exception as e:
                    level = "info"
                try:
                    taxonomies.append(
                        self.build_taxonomy(level, namespace, predicate, hash["data"])
                    )
                except Exception as e:
                    logging.warning(f"Error building taxonomy for {hash}: {e}")
        elif self.service == "all":
            predicate = "Analysis"
            for ioc_type in raw["iocs"]:
                for ioc in raw["iocs"][ioc_type]:
                    try:
                        if int(ioc["safe_score"]) >= self.threshold:
                            level = "safe"
                        elif int(ioc["suspicious_score"]) >= self.threshold:
                            level = "suspicious"
                        elif int(ioc["malicious_score"]) >= self.threshold:
                            level = "malicious"
                        else:
                            level = "info"
                    except Exception as e:
                        level = "info"
                    try:
                        taxonomies.append(
                            self.build_taxonomy(level, namespace, predicate, ioc["data"])
                        )
                    except Exception as e:
                        logging.warning(f"Error building taxonomy for {ioc}: {e}")
        return {"taxonomies": taxonomies}




    def analyze_values(args, types):
        """
        Analyze values.

        Parameters:
        args (Namespace): The arguments passed to the script.
        """
        table_values = []
        if types != "all":
            table_values.append(types)
        else:
            table_values = ["ips", "domains", "urls", "hashes"]
        logging.warning(f"Analyzing {table_values}...\n")
        api_key = get_api_key(args.api_key, args.api_key_file)
        proxy = get_proxy(args.proxy)
        case_number = str(args.case_id or 0).zfill(6)
        logging.warning(f"Begining case : #{case_number} ...\n")

        init = Initializator(api_key, proxy, case_number)

        # Get the values to analyze
        values = ValueReader(args.input_file, args.values).read_values()
        if not values:
            logging.warning("No values to analyze.")
            exit()

        # Analyze each value type
        results = dict()
        iocs = dict()
        for value_type in table_values:
            if not values[value_type]:
                logging.warning(f"No {value_type} to analyze.\n")
                continue

            logging.warning(f"Analyzing {len(values[value_type])} {value_type}...\n")
            value_results = []
            for value in values[value_type]:
                try:
                    if value_type == "hashes":
                        value_type_str = init.validator.validate_hash(value)
                    else:
                        validator_func = getattr(init.validator, f"validate_{value_type[:-1]}")
                        
                        value_type_str = validator_func(value)
                    if value_type_str:
                        if value_type_str in ["Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4", "Reserved IPv4", "MD5","SHA-1","SHA-224","SHA-384","SHA-512", "SSDEEP"]:
                            continue
                        else:
                            try:
                                value_results.append(init.reporter.get_report(value_type_str.upper(), value))
                            except Exception as e:
                                logging.warning(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
                    else:
                        logging.warning(f"Invalid {value_type[:-1]}: {value}\n")
                except Exception as e:
                    logging.warning(f"Error retrieving report for {value_type[:-1]}: {value}\n{e}")
            # Filter out invalid values
            value_results = [result for result in value_results if result]
            iocs[value_type] = value_results
        # Close the VirusTotal client
        init.client.close()
        results['iocs'] = iocs
        return results
            

        
    def run(self):
        """
        Run the analyzer.
        """

        args = argparse.Namespace(
            api_key=self.virustotal_key,
            proxy=self.proxies,
            case_id=self.case_id,
            input_file=self.file_path,
            values=[],
            api_key_file=None,
        )
        results = VTToolAnalyzer.analyze_values(args, self.service)
        try:
            self.report(results)
        except Exception as e:
            logging.warning(f"Error reporting results: {e}")

if __name__ == '__main__':
    VTToolAnalyzer().run()

            
