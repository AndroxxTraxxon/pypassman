import argparse
import shlex
import json
import os
import sys
import util
import hashlib

prompt_text  = "ppm >>> "

class SessionParser(argparse.ArgumentParser):

  class SessionError(UserWarning): pass

  def error(self, message):
    self.print_help(sys.stdout)
    raise self.SessionError(message)
  def exit(self, *args, **kwargs):
    pass # parser should never trigger a program exit. that is only done by the user.

session_parser = SessionParser(prompt_text)

def initialize_parser():
  session_parser.set_defaults(func=None, parser=session_parser)
  command_parsers = session_parser.add_subparsers()
  with open(os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "sessionCommands.json"
  )) as commands_file:
    commands = json.load(commands_file)
  for command in commands:
    cmd_parser = command_parsers.add_parser(command["name"], **command["properties"])
    if command.get("arguments"):
      for argument in command["arguments"]:
        cmd_parser.add_argument(argument["name"], **argument["properties"])
    cmd_parser.set_defaults(func=globals().get(command.get("function", command["name"])))

def write_entry(args, database, update_only:bool=False):
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
  results = database.search(filters)
  util.print_dictrows(
    results, 
    (
      'Username',
      'Hostname',
      'Date Modifed'
    )
  )

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
      args.parser.error("\nPassword Mismatch: Please enter the same password, or specify a file path.")
  else:
    args.parser.error("\n Error: Database path unknown. Cannot save without file path. (-d/--dest)")

def run(database, args, options = None):
  user_input = None
  initialize_parser()
  raw_user_input = input(prompt_text)
  while raw_user_input != "exit":
    try:
      user_input = shlex.split(raw_user_input)
      sess_args = session_parser.parse_args(user_input)
      if user_input[0] == 'save':
        if hasattr(args, 'sess_salt'):
          sess_args.sess_salt = args.sess_salt
        if hasattr(args, 'pass_hash'):
          sess_args.pass_hash = args.pass_hash
      if sess_args.func:
        sess_args.func(sess_args, database)
    except SessionParser.SessionError:
      print()
    raw_user_input = input(prompt_text)
    