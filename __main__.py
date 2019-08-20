import sys
import argparse
import interactions

parser = argparse.ArgumentParser(
    description="Interact with a pypassman Password Database", 
    prog="pypassman")
subparsers = parser.add_subparsers()
commands = {
    'init': subparsers.add_parser(
        'init',
        help="Initialize a password database file.'",
        aliases=['i']
        ),
    'session': subparsers.add_parser(
        'session',
        help="Start a pypassman session in the console",
        aliases=['s']
        ),
    'define': subparsers.add_parser(
        'define',
        help="Define a new user account in an existing password database.",
        aliases=['d', 'def']
        ),
    'query': subparsers.add_parser(
        'query',
        help="Search for a username or password in an existing password database.",
        aliases=['q']
        ),
    'update': subparsers.add_parser(
        'update',
        help='Update a password for a user account in an existing password database.',
        aliases=['u', 'up']
        )
}


# INIT COMMAND ARGUMENTS
commands["init"].add_argument('filepath',
    help='The relative filepath of the password database to be initialized'
    )
commands["init"].add_argument("-p, --pass",
    help='The master password of the database',
    metavar="PASSWORD",
    dest='masterpass'
    )
commands['init'].set_defaults(func=interactions.init)

# SESSION COMMAND ARGUMENTS
commands['session'].add_argument('-f, --file',
    help='Relative filepath of the password database, if not running in memory.',
    dest='filepath',
    metavar="FILEPATH"
)
commands['session'].add_argument('-p, --pass',
    help="Password for the file database, if not running in memory.",
    dest='masterpass',
    metavar="PASSWORD"
)

commands['session'].set_defaults(func=interactions.session)

# DEFINE COMMAND ARGUMENTS
commands['define'].add_argument('filepath',
    help="The relative filepath or the password database."
)
commands['define'].add_argument('hostname',
    help="The url or name of the host where the account resides."
)
commands['define'].add_argument('username', 
    help="The username of the account, what is typed in for login."
)
commands['define'].add_argument('-p, --pass, --masterpass',
    help="Password for the file password database, if not running in memory.",
    metavar="MASTER_PASS",
    dest='masterpass',
    default=None
)
commands['define'].add_argument('-userp, --userpass, --acctpass',
    help="Password to be added to the database",
    metavar="ACCOUNT_PASS",
    dest='accountpass',
    default=None
)

commands['define'].set_defaults(func=interactions.define)

# QUERY COMMAND ARGUMENTS
commands['query'].add_argument('filepath',
    help="The relative filepath or the password database."
)
commands['query'].add_argument('-s, --site, --host, --hostname',
    help="The url or name of the host where the account resides.",
    metavar="HOSTNAME",
    dest="hostname",
    default=None
)
commands['query'].add_argument('-u, --user, --username', 
    help="The username of the account, what is typed in for login.",
    metavar="USERNAME",
    dest="username",
    default=None
)
commands['query'].add_argument('-p, --pass, --masterpass',
    help="Password for the file password database, if not running in memory.",
    metavar="MASTER_PASS",
    dest='masterpass',
    default=None
)
commands['query'].set_defaults(func=interactions.query)

# UPDATE COMMAND ARGUMENTS
commands['update'].add_argument('filepath',
    help="The relative filepath or the password database."
)
commands['update'].add_argument('hostname',
    help="The url or name of the host where the account resides."
)
commands['update'].add_argument('username', 
    help="The username of the account, what is typed in for login."
)
commands['update'].add_argument('-p, --pass, --masterpass',
    help="Password for the file password database, if not running in memory.",
    metavar="MASTER_PASS",
    dest='masterpass',
    default=None
)
commands['update'].add_argument('-userp, --userpass, --acctpass',
    help="Password to be added to the database",
    metavar="ACCOUNT_PASS",
    dest='accountpass',
    default=None
)
commands['update'].set_defaults(func=interactions.update)

# pass an instance of the parser to the functions for errors
parser.set_defaults(parser=parser) 

if sys.argv[1:]:
    args = parser.parse_args(sys.argv[1:])
    args.func(args)
else:
    parser.print_usage()