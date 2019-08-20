import getpass

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
    confirmation = input("Are you sure you want to overwrite {}? (Y/n):".format(filename))
  return bool(confirmation == 'y')