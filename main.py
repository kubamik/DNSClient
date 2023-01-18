from DNSClient import DNSClient
from models import QTYPE

if __name__ == '__main__':
    client = DNSClient()
    print(client.retrieve('google.com', QTYPE.A))
    print(client.retrieve('pwr.edu.pl', QTYPE.MX))
