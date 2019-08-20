import argparse
import shlex
import json
import os
import sys
import util

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
  if args.hostname:
    filters.append(("hostname", args.hostname))
  if args.username:
    filters.append(("username", args.username))
  results = database.search(filters)
  print(results)

def save(args, database):
  password = util.get_master_password(args, verify=True)
  if args.filepath:
    path = os.path.realpath(args.filepath)
    if (not os.path.exists(path)) or util.confirm_overwrite_file(path):
      database.save_as(path, password)
  elif database.path:
    database.save(password)
  else:
    args.parser.error("DATABASE SAVE PATH NOT DEFINED")

def run(database, args, options = None):
  user_input = None
  initialize_parser()
  raw_user_input = input(prompt_text)
  while raw_user_input != "exit":
    try:
      user_input = shlex.split(raw_user_input)
      args = session_parser.parse_args(user_input)
      if args.func:
        args.func(args, database)
    except SessionParser.SessionError:
      print()
    raw_user_input = input(prompt_text)
    