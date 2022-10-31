from scapy.all import *
from scapy.layers.inet import IP, ICMP
from cryptography.fernet import Fernet


class ClientIcmp(object):

    @staticmethod
    def load_key():
        """ Loads the key from the current directory named `key.key` """

        return open("key.key", "rb").read()

    def encrypt_data(self, data):
        """ Encrypts the given data to be sent """

        key = Fernet(self.load_key())
        print(f"\nKey loaded is :{key}")
        return key.encrypt(data.encode())

    def send_icmp(self, dst_ip, data):
        """ Sends the ICMP packet with the data given """

        encrypt_data = self.encrypt_data(data)
        packet_icmp = IP(dst=dst_ip) / ICMP(type=47) / encrypt_data
        print(f"\nPacket to be sent is :\n {packet_icmp}")
        send(packet_icmp, count=1)

    def icmp_fun(self):
        """ Main method to get data and send modified ICMP packet """

        text = ""
        while text != "exit":
            dst_ip = input("\nEnter IP address to which the packet is to be sent:")
            text = input("\nEnter the Data to be send along with the ICMP packet else enter exit to exit:")
            if text == "exit":
                break
            self.send_icmp(dst_ip, text)
            print("Packet sent successfully")


if __name__ == "__main__":
    print("Client activated")
    client = ClientIcmp()
    client.icmp_fun()
