from typing import List
from prettytable import PrettyTable

class CustomPrettyTable:
    """
    A class for creating a table of data.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        self.headers = headers
        self.data = data

    def create_table(self, sort_by: str = None, reverse_sort: bool = False, align: str = 'l') -> str:
        """
        Create a table of data.

        Parameters:
        - sort_by (str): Column name to sort the table by.
        - reverse_sort (bool): Whether to sort the table in reverse order.
        - align (str): Alignment of columns ('l' for left, 'r' for right, 'c' for center).

        Returns:
        str: The table as a string.
        """
        table = PrettyTable()
        
        # Validate headers and data length
        if len(self.headers) != len(self.data[0]):
            raise ValueError("Number of headers must match the number of columns in data.")
        
        # Set headers and alignment
        table.field_names = self.headers
        table.align = align
        
        # Sort data if sort_by is specified
        if sort_by:
            sort_index = self.headers.index(sort_by)
            self.data.sort(key=lambda x: x[sort_index], reverse=reverse_sort)

        # Add rows to the table
        for row in self.data:
            table.add_row(row)
        
        return str(table)



