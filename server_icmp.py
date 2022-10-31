from scapy.all import *
from cryptography.fernet import Fernet


class ServerIcmp(object):

    @staticmethod
    def load_key():
        """ Loads the key from the current directory named `key.key` """

        return open("key.key", "rb").read()

    def decrypt_data(self, data):
        """ Decrypt the given data to sent """

        key = Fernet(self.load_key())
        print(f"\nKey loaded is :{key}")
        return key.decrypt(data)

    def icmp_fun(self):
        """ Main method for ICMP server """

        print("Sniffing data from ICMP packets")
        count = 0
        while 1:
            count += 1
            sniff_packet = sniff(count=1, filter="dst 192.168.1.101", iface="Wi-Fi")
            print(f"\nCount :{count} \n")
            print(f"Sniffed packet:\n{sniff_packet}\n{sniff_packet.show()}")
            enc_data = sniff_packet[0].getlayer(Raw)
            dec_data = self.decrypt_data(bytes(enc_data))
            print(f"\nDecrypted data :{dec_data.decode()}")


if __name__ == "__main__":
    server = ServerIcmp()
    server.icmp_fun()
