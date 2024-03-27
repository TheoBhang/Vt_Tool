import csv                          # for interacting with CSV files
from datetime import datetime       # for working with dates and times
from typing import Dict, List       # for defining types of variables

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
        now = datetime.now()  # Get the current time
        case_str = self.case_num.zfill(6)  # Zero-pad the case number to 6 digits
        # Format the date and time as a string
        today = now.strftime("%Y%m%d_%H%M%S")

        # Map value types to file name suffixes
        file_name_suffixes = {
            "IP": "IP_Analysis.csv",
            "HASH": "Hashes_Analysis.csv",
            "URL": "URL_Analysis.csv",
            "DOMAIN": "Domains_Analysis.csv"
        }
        # Get the file name suffix for the value type
        file_name_suffix = file_name_suffixes.get(value_type)

        # Raise an error if the value type is invalid
        if file_name_suffix is None:
            raise ValueError(f"Invalid value type: {value_type}")

        # Create the file path
        file_path = f"Results/{today}#{case_str}_{file_name_suffix}"
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
        # Write the contents of the table to a file in CSV format
        with open(file_path, 'w', newline='') as data_file:
            # Create the CSV writer object
            csv_writer = csv.DictWriter(
                data_file, fieldnames=data[0][0].keys(), delimiter=';')

            # Write the header row
            csv_writer.writeheader()
            for i in range(len(data)):
                # Write the data rows
                for obj in data[i]:
                    csv_writer.writerow(obj)

        #print(f"\nResults successfully printed in:\n\t{file_path}\n")

    def output_to_txt(self, data: List[List[str]], value_type: str) -> None:
        """
        Output data to a TXT file.

        Parameters:
        data (List[List[str]]): The data to output.
        value_type (str): The type of data to output.

        Returns:
        None
        """
        file_path = self._get_file_path(value_type)

        # Write the contents of the table to a file in TXT format
        with open(file_path.replace("csv", "txt"), "w", encoding="utf-8", newline="") as f:
            f.write(str(data))

        print(f"\nResults successfully printed in:\n\t{file_path}\n\t{file_path.replace('csv', 'txt')}\n")   
