import sys, os
from .passdb import PassDB

if __name__ == "__main__":
    a = PassDB()
    print(a)
    a.password = "password"
    a.set_entry("david", "localhost", "sample_password")
    # print(a.enc_str())
    a_copy = PassDB.open_db(a.enc_str(), "password")
    # print(a_copy.password)
    if a_copy is not None:
        print(a_copy.get_entry("david@localhost"))
        print(a_copy.get_password("david@localhost"))
        a_copy.save_as("tmp.passdb", "sample Password")
        