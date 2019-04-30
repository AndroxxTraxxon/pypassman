import base64
import hashlib
import pandas
from Crypto import Random
from Crypto.Cipher import AES
import json
import re
from io import StringIO
import datetime


class PassDB(object):

    _valid_init_fields = ["data", "path", "password", "settings"]
    version = "Version 0.0.1"
    settings: dict
    data: pandas.DataFrame
    _defaults = {
        "salt_size": 64,
        "block_size": 32,  # Using AES256
        "enc_sample_content": "The provided password is correct",
        "salt": None,
        "path": None,
        "hash_depth": 9
    }

    _format = """### PYPASSMAN {version} ###
{settings}
### SAMPLE ###
{enc_sample}
### DATA ###
{data}
"""

    def __init__(self, *args, **kwargs):
        if len(args) > 3:
            raise TypeError("Too Many Arguments")
        if len(args) > 2:
            self.data = args[2]
        else:
            self.data = None
        if len(args) > 1:
            self.password = args[1]
        else:
            self.password = None
        if len(args) > 0:
            self.path = args[0]
        else:
            self.path = None

        for key, arg in kwargs.items():
            if key in self._valid_init_fields:
                setattr(self, key, arg)

        if self.data is None:
            self.data = pandas.DataFrame(
                columns=[
                    "account",
                    "hostname",
                    "salt",
                    "password",
                    "hash_depth",
                    "dateModified",
                    "dateCreated"
                    ]
                )

        if getattr(self, "settings", None) is None:
            self.settings = self._defaults.copy()
        if self.settings.get("salt", None) is None:
            self.settings["salt"] = base64.b64encode(Random.new().read(
                self.settings["salt_size"]
            )).decode("utf-8")

        for key in self._defaults.keys():
            if key not in self.settings:
                self.settings[key] = self._defaults[key]

    @classmethod
    def open_db(cls, raw, password):
        settings, sample, data = (*map(
            lambda string: string.strip(),
            re.split(r"###.*###\n", raw)[1:]
            ),)
        settings = json.loads(settings)
        sample = cls._decrypt(sample, password, settings["salt"], settings["hash_depth"])
        if not sample == settings["enc_sample_content"]:
            raise ValueError(
                "Cannot open PassDB: incorrect password provided")
        data = cls._decrypt(data, password, settings["salt"], settings["hash_depth"])
        data = pandas.read_csv(StringIO(data))
        output = cls(
            settings=settings,
            data=data,
            password=password
        )
        return output

    def save_as(self, path, password):
        settings_cp = self.settings.copy()
        settings_cp["path"] = path
        new_dict = self.__class__(
            data = self.data,
            path = path,
            password = password,
            settings = settings_cp
        )
        new_dict.save()
        return True

    def save(self):
        with open(self.path, "w+") as dest:
            enc_data = self._encrypt(
                self.data.to_csv(index_label="index"),
                self.password, self.settings["salt"],
                self.settings["hash_depth"]
            )
            enc_sample = self._encrypt(
                self.settings["enc_sample_content"],
                self.password, self.settings["salt"],
                self.settings["hash_depth"])
            dest.write(self._format.format(
                version=str(self.version),
                settings=json.dumps(self.settings),
                data=enc_data,
                enc_sample=enc_sample
            ))

    @classmethod
    def _encrypt(cls, raw, password, salt, hash_depth):
        raw = cls._pad(raw)
        iv = Random.new().read(AES.block_size)
        salt = base64.b64decode(salt)
        key = hashlib.sha256(
                str(password).encode() + salt
            ).digest()
        for i in range(hash_depth):
            key = hashlib.sha256(key + salt).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    @classmethod
    def _decrypt(cls, enc, password, salt, hash_depth):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        salt = base64.b64decode(salt)
        key = hashlib.sha256(
                password.encode() + salt
            ).digest()
        for i in range(hash_depth):
            key = hashlib.sha256(key + salt).digest()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            return cls._unpad(
                cipher.decrypt(
                    enc[AES.block_size:]
                )
            ).decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Incorrect Password")

    @classmethod
    def _pad(cls, s):
        bs = cls._defaults["block_size"]
        return (
            s + (bs - len(s) % bs) *
            chr(bs - len(s) % bs)
            )

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def enc_str(self):
        enc_data = self._encrypt(
                self.data.to_csv(index_label="index"),
                self.password, self.settings["salt"],
                self.settings["hash_depth"]
            )
        enc_sample = self._encrypt(
                self.settings["enc_sample_content"],
                self.password, self.settings["salt"],
                self.settings["hash_depth"]
            )
        return (self._format.format(
                version=str(self.version),
                enc_sample=enc_sample,
                settings=json.dumps(self.settings),
                data=enc_data
            ))

    def __str__(self):
        path = self.settings["path"]
        return "PassDB <{} entries{}>".format(
            len(self.data), 
            " at '{}'".format(path) if path is not None else "" 
        )

    def set_entry(self, *args):
        account, hostname, password = None, None, None
        if len(args) == 1:
            account, hostname_password = args[0].split("@")
            hostname, password, other = hostname_password.split(":")
        elif len(args) == 2:
            account_hostname, password = args
            account, hostname = account_hostname.split("@")
        elif len(args) == 3:
            account, hostname, password = args
        else:
            raise ValueError("""
PassDB.set_entry :: Too many arguments 
    usage(1): get_password(account, hostname, password)
    usage(2): get_password("{account}@{hostname}", password)
    usage(3): get_password("{account}@{hostname}:{password}") """
                )

        for char in (":", "@"):
            for item in account, hostname, password:
                if char in item:
                    raise ValueError("""
account, hostname, and password cannot contain colon (:) or at symbol (@)""")
                            
        if len(self.data) > 0:
            for index, entry in self.data.iterrows():
                if entry["account"] == account and entry["hostname"] == hostname:
                    salt = base64.b64encode(Random.new().read(
                        self.settings["salt_size"]
                    )).decode("utf-8")
                    password = self._encrypt(
                        password, 
                        self.settings["salt"], 
                        salt, 
                        self.settings["hash_depth"]
                        )
                    self.data.loc[index] = (
                        account, hostname, 
                        salt, password, 
                        self.settings["hash_depth"],
                        str(datetime.datetime.utcnow().isoformat()),
                        str(datetime.datetime.utcnow().isoformat())
                    )
        else:
            salt = base64.b64encode(Random.new().read(
                self.settings["salt_size"]
            )).decode("utf-8")
            password = self._encrypt(
                password, 
                self.settings["salt"], 
                salt, 
                self.settings["hash_depth"]
                )
            self.data.loc[0] = (
                account,
                hostname,
                salt,
                password,
                self.settings["hash_depth"],
                str(datetime.datetime.utcnow().isoformat()),
                str(datetime.datetime.utcnow().isoformat())
            )

    def get_entry(self, *args):
        if len(args) == 1:
            account, hostname = args[0].split("@")
        elif len(args) == 2:
            account, hostname = args
        else:
            raise ValueError("""
PassDB.get_entry :: Too many arguments
    usage(1): get_entry(account, hostname)
    usage(2): get_entry("{account}@{hostname}")""")
        if(getattr(self, "password") is None):
            raise ValueError("Cannot get entry when PassDB instance password is None")
        if(len(self.data)) == 0:
            return None
        for index, entry in self.data.iterrows():
            if entry["account"] == account and entry["hostname"] == hostname:
                return entry
        return None
    
    def get_password(self, *args):
        if len(args) == 1:
            account, hostname = args[0].split("@")
        elif len(args) == 2:
            account, hostname = args
        else:
            raise ValueError("""
PassDB.get_password :: Too many arguments
    usage(1): get_password(account, hostname)
    usage(2): get_password("{account}@{hostname}")""")

        entry = self.get_entry(account, hostname)
        if isinstance(entry["password"], str):
            return self._decrypt(entry["password"], self.settings["salt"], entry["salt"], entry["hash_depth"])
        raise ValueError("Password for {account}@{hostname} in unexpected format".format(**entry))

