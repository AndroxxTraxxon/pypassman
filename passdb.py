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


class PassDB:

    version = "Version 0.0.1"
    settings: dict
    data: pandas.DataFrame
    _default_settings = {
        "salt_size": 64,
        "block_size": 32,  # Using AES256
        "enc_sample_content": "The provided password is correct",
        "salt": None,
        "path": None,
        "hash_depth": 9,
    }

    _format = """### PYPASSMAN {version} ###
{settings}
### CHECKSUM ###
{checksum}
### DATA ###
{data}
"""

    def __init__(
        self,
        data: pandas.DataFrame = pandas.DataFrame(
            columns=[
                "account",
                "hostname",
                "salt",
                "password",
                "hash_depth",
                "dateModified",
                "dateCreated",
            ]
        ),
        path: str = None,
        settings: dict = dict(),
    ):
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
                entry["hash_depth"],
            )
            encrypted_password = self._encrypt(
                decrypted_password,
                new_salt,
                new_password_salt,
                self.settings["hash_depth"],
            )
            del decrypted_password
            self.data.loc[index] = (
                entry["account"],
                entry["hostname"],
                new_password_salt,
                encrypted_password,
                self.settings["hash_depth"],
                str(datetime.datetime.utcnow().isoformat()),
                entry["dateCreated"],
            )
        self.settings["salt"] = new_salt
        self.pending_changes = True

    @classmethod
    def read_file(cls, path, password):
        result = None
        with open(path) as file:
            raw = file.read()
            result = cls.open_db(raw, password)
        return result

    @classmethod
    def open_db(cls, raw, password):
        settings_json, checksum, data_csv = (
            *map(lambda s: s.strip(), re.split(r"###.*###\n", raw)[1:]),
        )
        settings = json.loads(settings_json)
        checksum = base64.b64decode(checksum)
        data_csv = cls._decrypt(
            data_csv, password, settings["salt"], settings["hash_depth"]
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
    def _encrypt(cls, raw, password, salt, hash_depth):
        raw = cls._pad(raw)
        iv = Random.new().read(AES.block_size)
        salt = base64.b64decode(salt)
        key = hashlib.sha256(str(password).encode() + salt).digest()
        for i in range(hash_depth):
            key = hashlib.sha256(key + salt).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode("utf-8")

    @classmethod
    def _decrypt(cls, enc, password, salt, hash_depth):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        salt = base64.b64decode(salt)
        key = hashlib.sha256(password.encode() + salt).digest()
        for i in range(hash_depth):
            key = hashlib.sha256(key + salt).digest()

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
        data_csv = self.data.to_csv(index_label="index")
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
            self.settings["hash_depth"]
        )
        return self._format.format(
            version=str(self.version),
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
            raise ValueError(
                """
PassDB.set_entry :: Too many arguments
    usage(1): get_password(account, hostname, password)
    usage(2): get_password("{account}@{hostname}", password)
    usage(3): get_password("{account}@{hostname}:{password}") """
            )

        for char in (":", "@"):
            for item in account, hostname, password:
                if char in item:
                    raise ValueError(
                        """
account, hostname, and password cannot contain colon (:) or at symbol (@)"""
                    )

        if len(self.data) > 0:
            for index, entry in self.data.iterrows():
                if (entry["account"] == account and
                        entry["hostname"] == hostname):
                    salt = base64.b64encode(
                        Random.new().read(self.settings["salt_size"])
                    ).decode("utf-8")
                    password = self._encrypt(
                        password,
                        self.settings["salt"],
                        salt,
                        self.settings["hash_depth"],
                    )
                    self.data.loc[index] = (
                        account,
                        hostname,
                        salt,
                        password,
                        self.settings["hash_depth"],
                        str(datetime.datetime.utcnow().isoformat()),
                        str(datetime.datetime.utcnow().isoformat()),
                    )
        else:
            salt = base64.b64encode(
                Random.new().read(self.settings["salt_size"])
            ).decode("utf-8")
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
                str(datetime.datetime.utcnow().isoformat()),
            )

        self.pending_changes = True

    def get_entry(self, *args):
        if len(args) == 1:
            account, hostname = args[0].split("@")
        elif len(args) == 2:
            account, hostname = args
        else:
            raise ValueError(
                """
PassDB.get_entry :: Too many arguments
    usage(1): get_entry(account, hostname)
    usage(2): get_entry("{account}@{hostname}")"""
            )
        if (len(self.data)) == 0:
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
            raise ValueError(
                """
PassDB.get_password :: Too many arguments
    usage(1): get_password(account, hostname)
    usage(2): get_password("{account}@{hostname}")"""
            )

        entry = self.get_entry(account, hostname)
        if isinstance(entry["password"], str):
            return self._decrypt(
                entry["password"],
                self.settings["salt"],
                entry["salt"],
                entry["hash_depth"],
            )
        raise ValueError(
            "Password for {account}@{hostname} in \
                unexpected format".format(**entry)
        )
