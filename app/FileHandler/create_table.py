from typing import List

from prettytable import PrettyTable


class CustomPrettyTable:
    """
    A class for creating a table of data.
    """

    def __init__(self, headers: List[str], data: List[List[str]]):
        self.headers = headers
        self.data = data

    def divide_list(self, lst, n):
        return [lst[i : i + n] for i in range(0, len(lst), n)]

    def create_table(
        self, sort_by: str = None, reverse_sort: bool = False, align: str = "l"
    ) -> str:
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
        filtered_data = self.divide_list(self.data, len(self.headers))
        # Validate headers and data length
        if len(self.headers) != len(filtered_data[0]):
            raise ValueError(
                "Number of headers must match the number of columns in data."
            )

        # Set headers and alignment
        table.field_names = self.headers
        table.reversesort = True
        # Add rows to the table
        for row in filtered_data:
            table.add_row(row)
        return str(table)
