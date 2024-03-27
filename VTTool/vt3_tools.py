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
import argparse
import logging
from cortexutils.analyzer import Analyzer
from app.init import Initializator
from app.FileHandler.read_file import ValueReader
from app.DataHandler.utils import get_api_key, get_proxy


class VTToolAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param("config.service", None, "Service parameter is missing")
        self.virustotal_key = self.get_param("config.key", None, "Missing VirusTotal API key")
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
        taxonomies = []
        namespace = "VT_Tool"
        predicate = f"{self.service.capitalize()}_Analysis"

        for ioc_type in raw["iocs"]:
            for ioc in raw["iocs"][ioc_type]:
                try:
                    score = int(ioc.get("malicious_score", 0))
                    level = "safe" if score < self.threshold else "malicious"
                except ValueError:
                    level = "safe"
                except KeyError:
                    level = "safe"
                
                try:
                    taxonomies.append(self.build_taxonomy(level, namespace, predicate, ioc["data"]))
                except Exception as e:
                    logging.warning(f"Error building taxonomy for {ioc}: {e}")
        
        return {"taxonomies": taxonomies}

    @staticmethod
    def analyze_values(args, types):
        api_key = get_api_key(args.api_key, args.api_key_file)
        proxy = get_proxy(args.proxy)
        case_number = str(args.case_id or 0).zfill(6)

        init = Initializator(api_key, proxy, case_number)
        values = ValueReader(args.input_file, args.values).read_values()

        if not values:
            logging.warning("No values to analyze.")
            return {}

        results = {"iocs": {}}
        for value_type in types:
            results["iocs"][value_type] = []

            if not values.get(value_type):
                logging.warning(f"No {value_type} to analyze.")
                continue

            logging.warning(f"Analyzing {len(values[value_type])} {value_type}...")
            for value in values[value_type]:
                result = VTToolAnalyzer.analyze_value(init, value_type, value)
                if result:
                    results["iocs"][value_type].append(result)

        init.client.close()
        return results

    @staticmethod
    def analyze_value(init, value_type, value):
        try:
            value_type_str = init.validator.validate(value_type, value)
            if value_type_str and value_type_str not in ["Private IPv4", "Loopback IPv4", "Unspecified IPv4", "Link-local IPv4", "Reserved IPv4", "MD5", "SHA-1", "SHA-224", "SHA-384", "SHA-512", "SSDEEP"]:
                return init.reporter.get_report(value_type_str.upper(), value)
        except Exception as e:
            logging.warning(f"Error analyzing {value_type}: {value}\n{e}")
        return None

    def run(self):
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