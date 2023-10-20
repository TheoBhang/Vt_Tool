from typing import List             # for defining types of variables
from prettytable import PrettyTable as PT # for formatting results in a table

class PrettyTable:
    """
    A class for creating a table of data.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        self.headers = headers
        self.data = data

    def divide_list(self, lst, n):
        return [lst[i:i + n] for i in range(0, len(lst), n)]

    def create_table(self):
        """
        Create a table of data.

        Returns:
        str: The table as a string.
        """
        # Create the table
        table = PT()
        table.field_names = self.headers
        table.reversesort = True

        # Filter the data to only include rows with the same length as the headers list

        filtered_data = self.divide_list(self.data, len(self.headers))
        # Add the rows to the table
        for row in filtered_data:
            table.add_row(row)

        # Return the table as a string
        return str(table)



