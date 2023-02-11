from argparse import Action
from other import Options
from scapy.all import *

class Scan(Options):
    
    def __init__(self, ip, mac, spoof_ip, spoof_mac, ttl, colors) -> None:
        self.my_ip = ip
        super().__init__(ip, mac, spoof_ip, spoof_mac, ttl, colors)
        
    def arp(self):
        #print(self.my_ip)
        #print(self.colors.POINTGREEN("Iniciando el escaneo ARP"))
        print(self)

    def dir(self):
        print(self.__dir__())

    def __init__(self) -> None:
        pass
