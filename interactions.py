import os
import passdb
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

def get_master_password(args, verify=False):
    if hasattr(args, "masterpass") and args.masterpass:
        return args.masterpass
    if verify:
        return _request_new_password("master")
    else:
        return getpass.getpass("Password")

def get_user_password(args, account=None):
    if hasattr(args, "accountpass") and args.accountpass:
        return args.accountpass
    return _request_new_password(account)


def init(args):
    # check file path
    path = os.path.abspath(args.filepath)
    if os.path.exists(path):
        args.parser.error("FILE {} ALREADY EXISTS".format(path))
    # get user password
    # print("GEtting master password", args)
    password = get_master_password(args, verify=True)
    # create a new database and save it to the path, encrypting with password
    passdb.PassDB().save_as(path, password)

def write_entry(args, update_only:bool = True):
    path = os.path.abspath(args.filepath)
    if not os.path.exists(path):
        args.parser.error("FILE {} DOES NOT EXIST".format(path))
    # print(args)
    password = get_master_password(args)
    database = None
    try:
        database = passdb.PassDB.read_file(path, password)
        entry = database.get_entry(args.username, args.hostname)
        if update_only:
            if entry is None:
                args.parser.error("CANNOT UPDATE: ACCOUNT DOES NOT EXIST")
            else:
                database.set_entry(args.username, args.hostname, get_user_password(args, account=args.username))
        else:
            if entry is not None:
                args.parser.error("CANNOT DEFINE: ACCOUNT ALREADY EXISTS")
            else:
                database.set_entry(args.username, args.hostname, get_user_password(args, account=args.username))
    except TypeError:
        args.parser.error("INCORRECT PASSWORD")
    finally:
        database.save(password)
        print("Database saved at {}".format(database.path))

def define(args):
    write_entry(args, update_only=False)
    
def update(args):
    write_entry(args, update_only=True)

def query(args):
    path = os.path.abspath(args.filepath)
    if not os.path.exists(path):
        args.parser.error("FILE {} DOES NOT EXIST".format(path))
    
    password = get_master_password(args)
    database = None
    try:
        database = passdb.PassDB.read_file(path, password)
        filters = []
        if args.hostname:
            filters.append(("hostname", args.hostname))
        if args.username:
            filters.append(("username", args.username))
        results = database.search(filters)
        print(results)
        
    except TypeError as e:
        raise e
        args.parser.error("INCORRECT PASSWORD")
    return

def session(args):
    print("Session", args)
