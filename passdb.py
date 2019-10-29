import base64
import hashlib
import csv
from Crypto import Random
from Crypto.Cipher import AES
import json
import re
import datetime
import os
from io import StringIO
from typing import Iterable

__version__ = '0.0.1'

class PassDB:

    settings: dict
    data: list
    _default_settings = {
        "salt_size": 64,
        "block_size": 32,  # Using AES256
        "salt": None,
        "path": None,
        "hashDepth": 9,
    }
    _cols = {
        "user"  : "username",
        "host"  : "hostname",
        "salt"  : "salt",
        "pass"  : "password",
        "grp"   : "group",
        "depth" : "hashDepth",
        "mod"   : "dateModified",
        "create": "dateCreated",
        "sum"   : "checksum",
    }
    
    _format = """### PYPASSMAN Version {version} ###
{settings}
### CHECKSUM ###
{checksum}
### DATA ###
{data}
"""

    def __init__(
        self,
        data: list = None,
        path: str = None,
        settings: dict = None,
    ):
        if data is None:
            data = list()
        else:
            self.validate_data_shape(data)
        self.pending_changes = False
        self.data = data
        self.path = os.path.expanduser(path or '')

        self.settings = self._default_settings.copy()
        if settings:
            self.settings.update(settings)
        if self.settings.get("salt") is None:
            self.settings["salt"] = base64.b64encode(
                Random.new().read(self.settings["salt_size"])
            ).decode("utf-8")

    def gen_new_salt(self):
        new_salt = base64.b64encode(
            Random.new().read(self.settings["salt_size"])
        ).decode("utf-8")

        for index, entry in enumerate(self.data):
            new_password_salt = base64.b64encode(
                Random.new().read(self.settings["salt_size"])
            ).decode("utf-8")
            decrypted_password = self._decrypt(
                entry["password"],
                self.settings["salt"],
                entry["salt"],
                entry["hashDepth"],
            )
            encrypted_password = self._encrypt(
                decrypted_password,
                new_salt,
                new_password_salt,
                self.settings["hashDepth"],
            )
            del decrypted_password
            self.data[index] = {
                self._cols["user"]: entry[self._cols["user"]],
                self._cols["host"]: entry[self._cols["host"]],
                self._cols["salt"]: new_password_salt,
                self._cols["pass"]: encrypted_password,
                self._cols["depth"]: self.settings["hashDepth"],
                self._cols["mod"]: str(datetime.datetime.utcnow().isoformat()),
                self._cols["create"]: entry[self._cols["create"]],
            }
            self.data[index][self._cols["sum"]] = hashlib.sha256(
                str(self.data[index]).encode('utf-8')
            ).digest()
        self.settings["salt"] = new_salt
        self.pending_changes = True

    @classmethod
    def validate_data_shape(cls, data):
        pass

    @classmethod
    def read_file(cls, path, password):
        result = None
        with open(path) as file:
            raw = file.read()
            result = cls.open_db(raw, password)
            result.path = path
        return result

    @classmethod
    def open_db(cls, raw, password):
        settings_json, checksum, data_csv = (
            *map(lambda s: s.strip(), re.split(r"###.*###\n", raw)[1:]),
        )
        settings = json.loads(settings_json)
        checksum = base64.b64decode(checksum)
        data_csv = cls._decrypt(
            data_csv, password, settings["salt"], settings["hashDepth"]
        )
        checksum_calc = hashlib.sha256(
            str(data_csv + settings_json).encode("utf-8")
        ).digest()
        del settings_json
        if not checksum == checksum_calc:
            raise ValueError("Checksum does not match data.")
        data = []
        for row in csv.DictReader(StringIO(data_csv)):
            row[cls._cols['depth']] = int(row[cls._cols['depth']])
            data.append(row)
        return cls(settings=settings, data=data)

    def save_as(self, path, password):
        path = os.path.realpath(os.path.expanduser(path))
        settings_cp = self.settings.copy()
        settings_cp["path"] = path
        new_dict = self.__class__(
            data=self.data,
            path=path,
            settings=settings_cp
            )
        new_dict.gen_new_salt()
        new_dict.save(password)
        return new_dict

    def save(self, password):
        if not os.path.exists(os.path.dirname(self.path)):
            os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w+") as dest:
            dest.write(self.enc_str(password))
        self.pending_changes = False

    @classmethod
    def _deep_hash_digest(cls, key, salt, hashDepth):
        output = key
        hash_count = 0
        while hash_count < hashDepth:
            output = hashlib.sha256(output + salt).digest()
            hash_count += 1
        return output

    @classmethod
    def _encrypt(cls, raw, password, salt, hashDepth):
        raw = cls._pad(raw)
        iv = Random.new().read(AES.block_size)
        salt = base64.b64decode(salt)
        key = hashlib.sha256(str(password).encode() + salt).digest()
        key = cls._deep_hash_digest(key, salt, hashDepth)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    @classmethod
    def _decrypt(cls, enc, password, salt, hashDepth):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        salt = base64.b64decode(salt)
        key = hashlib.sha256(password.encode() + salt).digest()
        key = cls._deep_hash_digest(key, salt, hashDepth)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            return cls._unpad(
                cipher.decrypt(
                    enc[AES.block_size:]
                    )
                ).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Unable to decrypt")

    @classmethod
    def _pad(cls, s):
        bs = cls._default_settings["block_size"]
        return bytes(s + (bs - len(s) % bs) * chr(bs - len(s) % bs), 'utf-8')

    @classmethod
    def _unpad(cls, s):
        return s[: -ord(s[len(s) - 1:])]

    def enc_str(self, password):
        data_csv = ''
        with StringIO() as tmp_io:
            fieldNames = self._cols.values()
            writer = csv.DictWriter(tmp_io, fieldNames)
            writer.writeheader()
            writer.writerows(self.data)
            data_csv = tmp_io.getvalue()
        settings_json = json.dumps(self.settings)
        checksum = base64.b64encode(
            hashlib.sha256(
                str(data_csv + settings_json).encode("utf-8")
            ).digest()
        ).decode("utf-8")

        enc_data = self._encrypt(
            data_csv,
            password,
            self.settings["salt"],
            self.settings["hashDepth"]
        )
        return self._format.format(
            version=__version__,
            checksum=checksum,
            settings=settings_json,
            data=enc_data,
        )

    def __str__(self):
        path = self.settings["path"]
        return "PassDB <{}{}>".format(
            "{} entr{}".format(
                len(self.data),
                "y" if len(self.data) == 1 else "ies"
                )
            if len(self.data) > 0
            else "Empty",
            " at {}'{}'".format("*" if self.pending_changes else "", path)
            if path is not None
            else "",
        )

    def set_entry(self, account, hostname, password):
        index = 0
        while index < len(self.data):
            entry = self.data[index]
            if (entry[self._cols["user"]] == account and entry[self._cols["host"]] == hostname):
                break
            index += 1
        if index == len(self.data):
            # If we're adding a new item, extend the list.
            self.data.append(None) 
        salt = base64.b64encode(
            Random.new().read(self.settings["salt_size"])
        ).decode("utf-8")
        password = self._encrypt(
            password,
            self.settings["salt"],
            salt,
            self.settings["hashDepth"],
        )
        self.data[index] = {
            self._cols["user"]   : account, 
            self._cols["host"]   : hostname, 
            self._cols["salt"]   : salt, 
            self._cols["pass"]   : password, 
            self._cols["depth"]  : self.settings["hashDepth"],
            self._cols["mod"]    : str(datetime.datetime.utcnow().isoformat()),  
            self._cols["create"] : str(datetime.datetime.utcnow().isoformat()),
        }
        self.data[index][self._cols["sum"]] = base64.b64encode(
            hashlib.sha256(
                str(self.data[index]).encode('utf-8')
            ).digest()
        )
        
    def get_entry(self, account:str, hostname:str):
        for entry in self.data:
            if entry[self._cols["user"]] == account and entry[self._cols["host"]] == hostname:
                return entry
        return None

    @staticmethod
    def matchEntry(item:dict, column_name:str, search_value):
        return str(search_value) in str(item[column_name])
    @staticmethod
    def onlyKeys(keys:Iterable[str], item: dict):
        selectedValues = dict()
        for key in keys:
            selectedValues[key] = item.get(key)
        return selectedValues

    def search(self, filters:Iterable[tuple]):
        search_results = self.data.copy()
        for item in filters:
            search_results = filter((lambda i: self.matchEntry(i, *item)), search_results)
        return [*map(lambda x: self.onlyKeys(("username", "hostname", "dateModified"), x), search_results)]

    def get_password(self, account:str, hostname:str):
        entry = self.get_entry(account, hostname)
        if entry and isinstance(entry["password"], str):
            return self._decrypt(
                entry["password"],
                self.settings["salt"],
                entry["salt"],
                entry["hashDepth"],
            )
        raise ValueError(
            "Password for {account}@{hostname} in \
                unexpected data type".format(**entry)
        )

