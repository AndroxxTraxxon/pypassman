import os
import passdb
import getpass
import userSession
import util
import hashlib
import base64
from Crypto import Random

def init(args):
    # check file path
    path = os.path.realpath(os.path.expanduser(args.filepath))
    if os.path.exists(path):
        if args.force :
            if not util.confirm_overwrite_file(path):
                args.parser.error("ACTION ABORTED: INIT AT {}".format(path))
        else:
            args.parser.error("FILE {} ALREADY EXISTS".format(path))
    # get user password
    password = util.get_master_password(args, verify=True)
    # create a new database and save it to the path, encrypting with password
    passdb.PassDB().save_as(path, password)
    print("Database initialized at %s" % path)

def write_entry(args, update_only:bool = True):
    path = os.path.realpath(os.path.expanduser(args.filepath))
    if not os.path.exists(path):
        args.parser.error("FILE {} DOES NOT EXIST".format(path))
    # print(args)
    password = util.get_master_password(args)
    database = None
    try:
        database = passdb.PassDB.read_file(path, password)
        entry = database.get_entry(args.username, args.hostname)
        if update_only:
            if entry is None:
                args.parser.error("CANNOT UPDATE: ACCOUNT DOES NOT EXIST")
            else:
                database.set_entry(args.username, args.hostname, util.get_user_password(args, account=args.username))
        else:
            if entry is not None:
                args.parser.error("CANNOT DEFINE: ACCOUNT ALREADY EXISTS")
            else:
                database.set_entry(args.username, args.hostname, util.get_user_password(args, account=args.username))
        database.save(password)
    except ValueError:
        args.parser.error("INCORRECT PASSWORD")
    finally:
        print("Database saved at {}".format(database.path))

def define(args):
    write_entry(args, update_only=False)
    
def update(args):
    write_entry(args, update_only=True)

def query(args):
    path = os.path.realpath(os.path.expanduser(args.filepath))
    if not os.path.exists(path):
        args.parser.error("FILE {} DOES NOT EXIST".format(path))
    
    password = util.get_master_password(args)
    database = None
    try:
        database = passdb.PassDB.read_file(path, password)
        filters = []
        if hasattr(args, "hostname") and args.hostname:
            filters.append(("hostname", args.hostname))
        if hasattr(args, "username") and args.username:
            filters.append(("username", args.username))
        results = database.search(filters)
        print(results)
        
    except ValueError:
        args.parser.error("INCORRECT PASSWORD")
    return

def session(args):
    # print(args)
    database = None
    if args.filepath is not None:
        path = os.path.realpath(os.path.expanduser(args.filepath))
        if not os.path.exists(path):
            args.parser.error("FILE {} DOES NOT EXIST".format(path))
        password=util.get_master_password(args)
        session_salt = base64.b64encode(
            Random.new().read(64)
        ).decode("utf-8")
        args.pass_hash = hashlib.sha256((password + session_salt).encode('utf-8')).digest()
        args.sess_salt = session_salt
        try:
            database = passdb.PassDB.read_file(path, password)
        except ValueError:
            print("pypassman: error: INCORRECT PASSWORD")
            exit(1)
    else:
        database = passdb.PassDB()
    userSession.run(database, args)
