import getpass
from typing import Iterable, Dict

_names_to_types = {
  "int": int,
  "str": str,
  "float": float,
  "bool": bool,
  "Nonetype": type(None)
}

def get_type(typename:str):
  return _names_to_types.get(typename) or typename

_cols = {
    "user"  : "username",
    "host"  : "hostname",
    "salt"  : "salt",
    "pass"  : "password",
    "grp"   : "group",
    "depth" : "hashDepth",
    "meta"  : "metadata",
    "mod"   : "dateModified",
    "create": "dateCreated",
    "sum"   : "checksum",
  }
def column_names():
  return _cols.copy()

def _request_new_password(title=None):
  while True:
    first_password = None
    while not first_password:
      first_password = getpass.getpass("Please enter password{}:".format(
        "" if not title else " for {}".format(title)
      ))
    second_password = getpass.getpass("Please re-enter password:")
    if(first_password == second_password):
      return second_password
    else:
      print("Passwords did not match. Please try again.")

def get_user_password(args, account=None):
  if hasattr(args, "accountpass") and args.accountpass:
    return args.accountpass
  return _request_new_password(account)

def get_master_password(args, verify=False):
  if hasattr(args, "masterpass") and args.masterpass:
    return args.masterpass
  if verify:
    return _request_new_password("master")
  else:
    return getpass.getpass("Master Password: ")

def confirm_overwrite_file(filename):
  confirmation = None
  while not confirmation or confirmation.lower() not in ('y', 'n'):
    confirmation = input("Are you sure you want to overwrite {}?\n (Y/n):".format(filename)).lower()[0]
  return bool(confirmation == 'y')

def print_dictrows(dictrows:Iterable[Dict], columns:Iterable[str] = None, empty_alt:str = 'Empty Table') -> None:
  rows_to_print = list()
  if dictrows:
    if not columns:
      columns = (x for x in dictrows[0].keys())
    for row in dictrows:
      _row = []
      for value in row.values():
        _row.append(value)
      rows_to_print.append(_row)

  else:
    if not columns:
      print('| %s |' % empty_alt)
      return
    rows_to_print.append(["Empty" for x in columns])
  print_table(rows_to_print, headers=columns)

def print_table(tableData:Iterable[list], headers = None):
  if headers:
    tableData.insert(0, (*headers, ))
  colWidths = [0] * len(tableData[0])
  for rowData in tableData:
    for i, colItem in enumerate(rowData):
      itemLength = len(str(colItem))
      if itemLength > colWidths[i]:
        colWidths[i] = itemLength      
  numRows = len(tableData)
  numCols = len(tableData[0])      
  for rowIndex in range(numRows):
    for colIndex in range(numCols):
      print(str(tableData[rowIndex][colIndex]).ljust(colWidths[colIndex]), end='  ')
    print()
    if headers and rowIndex == 0:
      for colIndex in range(numCols):
        print('_' * colWidths[colIndex], end ='__')
      print()

def print_pass_entry(index: int, entry:dict):
  output = {
    "Index": index,
    "Username"      : entry[_cols['user']],
    "Hostname"      : entry[_cols['host']],
    "Group"         : entry[_cols['grp']],
    "Last Modified" : entry[_cols['mod']]
  }
  return print_dictrows([output])