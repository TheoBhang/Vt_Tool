import csv
from datetime import datetime
from typing import Dict, List


class OutputHandler:
    """
    A class for outputting data to files (CSV / TXT).

    Attributes:
        case_num (str): The case number.
        csvfilescreated (List[str]): A list of CSV files created by the script.

    Methods:
        _get_file_path(value_type): Get the file path for a given value type.
        output_to_csv(data, value_type): Output data to a CSV file.
        output_to_txt(data, value_type): Output data to a TXT file.

    """

    def __init__(self, case_num: str):
        self.case_num = case_num
        self.csvfilescreated = []

    def _get_file_path(self, value_type: str) -> str:
        """
        Get the file path for a given value type.

        Parameters:
        value_type (str): The type of data to output.

        Returns:
        str: The file path.
        """
        now = datetime.now()
        case_str = self.case_num.zfill(6)
        today = now.strftime("%Y%m%d_%H%M%S")

        file_name_suffixes = {
            "IP": "IP_Analysis",
            "HASH": "Hashes_Analysis",
            "URL": "URL_Analysis",
            "DOMAIN": "Domains_Analysis",
        }
        file_name_suffix = file_name_suffixes.get(value_type)

        if file_name_suffix is None:
            raise ValueError(f"Invalid value type: {value_type}")

        file_path = f"Results/{case_str}_{file_name_suffix}_{today}.csv"
        self.csvfilescreated.append(file_path)

        return file_path

    def output_to_csv(self, data: List[Dict[str, str]], value_type: str) -> None:
        """
        Output data to a CSV file.

        Parameters:
        data (List[Dict[str, str]]): The data to output.
        value_type (str): The type of data to output.

        Returns:
        None
        """
        file_path = self._get_file_path(value_type)
        try:
            with open(file_path, "w", newline="") as data_file:
                csv_writer = csv.DictWriter(
                    data_file, fieldnames=data[0][0].keys(), delimiter=","
                )
                csv_writer.writeheader()
                for obj in data:
                    csv_writer.writerow(obj[0])
        except Exception as e:
            print(f"Error occurred while writing CSV file: {e}")

        print(f"\nResults successfully printed in:\n\t{file_path}\n")

    def output_to_txt(self, data: List[List[str]], value_type: str) -> None:
        """
        Output data to a TXT file.

        Parameters:
        data (List[List[str]]): The data to output.
        value_type (str): The type of data to output.

        Returns:
        None
        """
        file_path = self._get_file_path(value_type).replace(".csv", ".txt")

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(str(data))
        except Exception as e:
            print(f"Error occurred while writing TXT file: {e}")

        print(f"\nResults successfully printed in:\n\t{file_path}\n")
