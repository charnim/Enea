import csv
from openpyxl import Workbook


class Csv(object):

    """Csv class for handling csv files"""

    def __init__(self, csv_path):

        self.path = csv_path

        self.CsvName = csv_path.split('\\')[-1]

        self.CellsAsList = self.csv_all_cells_from()

        self.CellsAsListNoNumbers = self.csv_all_cells_from_no_numbers()

    @staticmethod
    def _dup_remover(list_a):

        """Simple remover of duplicates from list"""

        return list(set(list_a))

    def csv_all_cells_from(self):

        """Will extract all fields and return a list"""

        final_cells_in_list = []

        with open(self.path, 'r', encoding="utf-8") as f:
            for row in csv.reader(f):

                for index in range(len(row)):

                    if (row[index] is not None) and (row[index] is not ''):

                        row[index] = str(row[index])

                final_cells_in_list = final_cells_in_list+row

        return self._dup_remover(final_cells_in_list)

    def csv_all_cells_from_no_numbers(self):

        """Will extract all fields except for numbers and return a list"""

        final_cells_in_list = []
        with open(self.path, 'r', encoding="utf-8") as f:
            for row in csv.reader(f):

                for index in range(len(row)):

                    if (row[index] is not None) and (row[index] is not ''):

                        try:

                            int(row[index])

                        except TypeError:

                            final_cells_in_list.append(str(row[index]))

                        except ValueError:

                            final_cells_in_list.append(str(row[index]))

        return self._dup_remover(final_cells_in_list)

    def csv_to_excel(self):

        excel_file_name = self.CsvName.split('.')
        if excel_file_name[-1] == 'csv':

            excel_file_name = excel_file_name[0]+'.xlsx'

            wb = Workbook()
            ws = wb.create_sheet('main', 0)

            with open(self.CsvName, 'r', encoding="utf8") as f:
                for row in self.CsvName.reader(f):
                    ws.append(row)
            wb.save(excel_file_name)

            return excel_file_name
        else:
            print('The file doesnt have the extension of "csv"')
