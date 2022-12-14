from cryptography.fernet import Fernet


class Genkey(object):

    @staticmethod
    def write_key():
        """
           Generates a key and save it into a file
        """

        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)


if __name__ == "__main__":
    gen_key = Genkey()
    gen_key.write_key()
