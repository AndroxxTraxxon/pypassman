from .passdb import PassDB

if __name__ == "__main__":
    a = PassDB()
    print(a)
    a.set_entry("david", "localhost", "sample_password")
    a.save_as("tmp.passdb", "file_password")

    b = PassDB.read_file("tmp.passdb", "file_password")
    print(b)
    print(b.get_entry("david@localhost"))
    print(b.get_password("david@localhost"))
        