import base64
import hashlib
import pandas
from Crypto import Random
from Crypto.Cipher import AES
import json
import re
from io import StringIO
import datetime
import os

__version__ = '0.0.1'

class PassDB:

    settings: dict
    data: pandas.DataFrame
    _default_settings = {
        "salt_size": 64,
        "block_size": 32,  # Using AES256
        "salt": None,
        "path": None,
        "hashDepth": 9,
    }
    __user_col = "username"
    __site_col = "hostname"
    __column_names = [
        __user_col,
        __site_col,
        "salt",
        "password",
        "hashDepth",
        "dateModified",
        "dateCreated",
    ]
    _format = """### PYPASSMAN Version {version} ###
{settings}
### CHECKSUM ###
{checksum}
### DATA ###
{data}
"""

    def __init__(
        self,
        data: pandas.DataFrame=None,
        path: str = None,
        settings: dict = dict(),
    ):
        if data is None:
            data = pandas.DataFrame = pandas.DataFrame(
                columns=self.__column_names
            )
        else:
            self.validate_data_shape(data)
        self.pending_changes = False
        self.data = data
        self.path = path

        self.settings = self._default_settings.copy()
        self.settings.update(settings)
        if self.settings.get("salt") is None:
            self.settings["salt"] = base64.b64encode(
                Random.new().read(self.settings["salt_size"])
            ).decode("utf-8")

    def gen_new_salt(self):
        new_salt = base64.b64encode(
            Random.new().read(self.settings["salt_size"])
        ).decode("utf-8")

        for index, entry in self.data.iterrows():
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
            self.data.loc[index] = (
                entry[self.__user_col],
                entry[self.__site_col],
                new_password_salt,
                encrypted_password,
                self.settings["hashDepth"],
                str(datetime.datetime.utcnow().isoformat()),
                entry["dateCreated"],
            )
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
        data = pandas.read_csv(StringIO(data_csv))
        return cls(settings=settings, data=data)

    def save_as(self, path, password):
        path = os.path.realpath(path)
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
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1:])]

    def enc_str(self, password):
        data_csv = self.data.to_csv(index=False)
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
        if len(self.data) > 0:
            entry_recorded = False
            for index, entry in self.data.iterrows():
                if (entry[self.__user_col] == account and
                        entry[self.__site_col] == hostname):
                    salt = base64.b64encode(
                        Random.new().read(self.settings["salt_size"])
                    ).decode("utf-8")
                    password = self._encrypt(
                        password,
                        self.settings["salt"],
                        salt,
                        self.settings["hashDepth"],
                    )
                    self.data.loc[index] = (
                        account,
                        hostname,
                        salt,
                        password,
                        self.settings["hashDepth"],
                        str(datetime.datetime.utcnow().isoformat()),
                        str(datetime.datetime.utcnow().isoformat()),
                    )
            if not entry_recorded: # append, if not found in database
                salt = base64.b64encode(
                        Random.new().read(self.settings["salt_size"])
                    ).decode("utf-8")
                password = self._encrypt(
                    password,
                    self.settings["salt"],
                    salt,
                    self.settings["hashDepth"],
                )
                self.data = self.data.append({
                    self.__column_names[0]:account,
                    self.__column_names[1]:hostname,
                    self.__column_names[2]:salt,
                    self.__column_names[3]:password,
                    self.__column_names[4]:self.settings["hashDepth"],
                    self.__column_names[5]:str(datetime.datetime.utcnow().isoformat()),
                    self.__column_names[6]:str(datetime.datetime.utcnow().isoformat()),
                }, ignore_index=True)
        else:
            salt = base64.b64encode(
                Random.new().read(self.settings["salt_size"])
            ).decode("utf-8")
            password = self._encrypt(
                password,
                self.settings["salt"],
                salt,
                self.settings["hashDepth"]
            )
            self.data.loc[0] = (
                account,
                hostname,
                salt,
                password,
                self.settings["hashDepth"],
                str(datetime.datetime.utcnow().isoformat()),
                str(datetime.datetime.utcnow().isoformat()),
            )

        self.pending_changes = True

    def get_entry(self, account, hostname):
        if (len(self.data)) == 0:
            return None
        for entry in self.data.iterrows():
            if entry[1]["username"] == account and entry[1]["hostname"] == hostname:
                return entry[1]
        return None

    def search(self, filters):
        search_results = self.data.copy()
        for filter in filters:
            search_results = search_results.loc[search_results[filter[0]].str.contains(filter[1])]
        return search_results.filter(["username", "hostname", "dateModified"])

    def get_password(self, account, hostname):
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

