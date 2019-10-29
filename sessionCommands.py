commands = [
  {
    "name": "define",
    "properties": {
      "help": "Define a new user account",
      "aliases": [
        "d",
        "def"
      ]
    },
    "arguments":[
      {
        "name":"hostname",
        "properties":{
          "help": "The url or name of the host where the account resides."
        }
      },
      {
        "name":"username",
        "properties":{
          "help":"The username of the account, what is typed in for login."
        }
      },
      {
        "name":"-userp, --userpass, --acctpass",
        "properties":{
          "help":"Password to be added to the database",
          "metavar":"ACCOUNT_PASS",
          "dest":"accountpass"
        }
      },
      {
        "name":"-g, --grp, --group",
        "properties":{
          "help":"The name of the group to add to the database, for search purposes",
          "metavar":"GROUP",
          "dest":"group",
          "default": None
        }
      }
    ]
  },
  {
    "name":"query",
    "properties": {
      "help": "Search for a username or password",
      "aliases":["q"]
    },
    "arguments":[
      {
        "name":"-s, --site, --host, --hostname",
        "properties":{
          "help":"The url or name of the host where the account resides.",
          "metavar":"HOSTNAME",
          "dest":"hostname"
        }
      },
      {
        "name":"-u, --user, --username", 
        "properties":{
          "help":"The username of the account, what is typed in for login.",
          "metavar":"USERNAME",
          "dest":"username"
        }
      },
      {
        "name":"-g, --grp, --group", 
        "properties":{
          "help":"The group of the account.",
          "metavar":"GROUP",
          "dest":"group"
        }
      }
    ]
  },
  {
    "name": "read",
    "properties":{
      "help":"Read a specific entry from the database.",
      "aliases":["r"],
      "epilog": "Required: entry index[-i] OR (site[-s] AND username[-u])"
    },
    "arguments":[
      {
        "name":"-s, --site, --host, --hostname",
        "properties":{
          "help":"The url or name of the host where the account resides.",
          "metavar":"HOSTNAME",
          "dest":"hostname",
          "default": None
        }
      },
      {
        "name":"-u, --user, --username", 
        "properties":{
          "help":"The username of the account, what is typed in for login.",
          "metavar":"USERNAME",
          "dest":"username",
          "default": None
        }
      },
      {
        "name":"-i, --index",
        "properties":{
          "help":"The row number of the password entry, starting at 0",
          "metavar": "INDEX",
          "dest": "index",
          "type": "int",
          "default": None
        }
      }
    ]
  },
  {
    "name": "update",
    "properties":{
      "help": "Update a password for an existing user account",
      "aliases": [
        "u",
        "up"
      ]
    },
    "arguments":[
      {
        "name":"hostname",
        "properties":{
          "help": "The url or name of the host where the account resides."
        }
      },
      {
        "name":"username",
        "properties":{
          "help":"The username of the account, what is typed in for login."
        }
      },
      {
        "name":"-userp, --userpass, --acctpass",
        "properties":{
          "help":"Password to be added to the database",
          "metavar":"ACCOUNT_PASS",
          "dest":"accountpass"
        }
      },
      {
        "name":"-g, --grp, --group",
        "properties":{
          "help":"The name of the group to add to the database, for search purposes",
          "metavar":"GROUP",
          "dest":"group",
          "default": None
        }
      }
    ]
  },
  {
    "name": "save",
    "properties":{
      "help": "Save the database"
    },
    "arguments":[
      {
        "name":"-d, --dest, --destination",
        "properties":{
          "help": "The destination file path for the database file.",
          "metavar": "FILEPATH",
          "dest":"filepath"
        }
      },
      {
        "name":"-p, --password, --masterpass",
        "properties":{
          "help":"Password with which to encrypt the database.",
          "metavar":"MASTERPASS",
          "dest":"masterpass"
        }
      }
    ]
  },
  {
    "name": "close",
    "properties": {
      "help": "Close the pypassman user session",
      "aliases":[
        "exit",
        "quit"
      ]
    },
    "arguments": [
      {
        "name": "-s, --save",
        "properties":{
          "help": "Save the database upon exiting",
          "action": "store_true",
          "dest": "save",
          "default": False
        }
      }
    ]
  }
]