import argparse
import shlex
import json
import os
import sys
import util
import hashlib
import pyperclip

prompt_text  = "ppm >>> "

class SessionParser(argparse.ArgumentParser):

  class SessionError(UserWarning): pass

  def error(self, message):
    print(message)
    self.print_help(sys.stdout)
    raise self.SessionError(message)
  def exit(self, *args, **kwargs):
    pass # parser should never trigger a program exit. that is only done by the user.

session_parser = SessionParser(prompt_text, add_help=False)

def initialize_parser():
  session_parser.set_defaults(func=None, parser=session_parser)
  command_parsers = session_parser.add_subparsers()
  from sessionCommands import commands
  for command in commands:
    cmd_parser = command_parsers.add_parser(command["name"], **command["properties"])
    if command.get("arguments"):
      for argument in command["arguments"]:
        prop_type = argument["properties"].get("type")
        if prop_type:
          argument["properties"]["type"] = util.get_type(prop_type)
        cmd_parser.add_argument(argument["name"], **argument["properties"])
    cmd_parser.set_defaults(func=globals().get(command.get("function", command["name"])))

def write_entry(args, database, update_only:bool=False):
  index, entry = database.get_entry(args.username, args.hostname)
  if update_only:
    if entry is None:
      args.parser.error("CANNOT UPDATE: ACCOUNT DOES NOT EXIST")
    else:
      database.set_entry(args.username, args.hostname, util.get_user_password(args, account=args.username), group=args.group)
  else:
    if entry is not None:
      args.parser.error("CANNOT DEFINE: ACCOUNT ALREADY EXISTS")
      
    else:
      database.set_entry(args.username, args.hostname, util.get_user_password(args, account=args.username), group=args.group)

def define(args, database):
  write_entry(args, database, update_only=False)

def update(args, database):
  write_entry(args, database,  update_only=True)

def query(args, database):
  filters = []
  if hasattr(args, 'hostname') and args.hostname:
    filters.append(("hostname", args.hostname))
  if hasattr(args, 'username') and args.username:
    filters.append(("username", args.username))
  if hasattr(args, 'group') and args.group:
    filters.append(("group", args.group))
  results = database.search(filters)
  util.print_dictrows(
    results, 
    (
      'Index',
      'Username',
      'Hostname',
      'Group',
      'Date Modifed'
    )
  )

def read(args, database):
  index, entry = None, None
  if args.index is not None:
    if args.username or args.hostname:
      return args.parser.error('Cannot specify username or hostname when INDEX is defined.')
    else:
      if isinstance(args.index, int) or args.index < 0:
        try:
          index, entry = args.index, database.get_entry_by_index(args.index)
        except IndexError:
          return print('Entry not found.')
      else:
        return args.parser.error('Index must be a positive integer.')
  elif args.username and args.hostname:
    index, entry = database.get_entry(args.username, args.hostname)
    if index is None:
      return print('Entry not found.')
  else:
    return args.parser.error('Ambiguous query. Required: entry index[-i] OR (site[-s] AND username[-u]).')
  password = database.get_password((index, entry))
  util.print_pass_entry(index, entry)
  pyperclip.copy(password)
  print("The password for the above account has be copied to the clipboard.")


def save(args, database):
  if args.filepath:
    password = util.get_master_password(args, verify=True)
    path = os.path.realpath(os.path.expanduser(args.filepath))
    if (not os.path.exists(path)) or util.confirm_overwrite_file(path):
      database.save_as(path, password)
  elif database.path:
    password = util.get_master_password(args)
    if args.sess_salt and hashlib.sha256((password + args.sess_salt).encode('utf-8')).digest() == args.pass_hash:
      database.save(password)
      print('Database saved at %s'%database.path)
    else:
      args.parser.error("\nPassword Mismatch: Please enter the same password used to open the database, or specify a file path.")
  else:
    args.parser.error("\n Error: Database path unknown. Cannot save without file path. (-d/--dest)")

def close(args, database):
  pyperclip.copy("")
  if args.save:
    password = util.get_master_password(args)
    if args.sess_salt and hashlib.sha256((password + args.sess_salt).encode('utf-8')).digest() == args.pass_hash:
      database.save(password)
      print('Database saved at %s'%database.path)
      sys.exit()
    else:
      args.parser.error("\nPassword Mismatch: Please enter the same password used to open the database.")
  else:
    sys.exit()
  

def run(database, args, options = None):
  user_input = None
  initialize_parser()
  raw_user_input = input(prompt_text)
  while True:
    try:
      user_input = shlex.split(raw_user_input)
      sess_args = session_parser.parse_args(user_input)
      if user_input and user_input[0] in ('save', 'close'):
        if hasattr(args, 'sess_salt'):
          sess_args.sess_salt = args.sess_salt
        if hasattr(args, 'pass_hash'):
          sess_args.pass_hash = args.pass_hash
      help_flag = False
      for flag in ("-h", "--help"):

        if flag in user_input:
          help_flag = True
          break
      if not help_flag and sess_args.func and callable(sess_args.func):
        sess_args.func(sess_args, database)
    except SessionParser.SessionError:
      print()
    raw_user_input = input(prompt_text)
    