from other import Options
from scapy.all import *

class Scan(Options):
    
    def __init__(self,
            ip=None,
            mac=None,
            spoof_ip=None,
            spoof_mac=None,
            iface=None,
            ttl=None,
            ttl_random=None,
            ip_objetivo=None,
            ip_range=None
        ) -> None:
        super(Scan,self).__init__(
            ip=ip, 
            mac=mac, 
            spoof_ip=spoof_ip, 
            spoof_mac=spoof_mac, 
            ttl=ttl, 
            iface=iface,
            ttl_random=ttl_random,
            ip_objetivo=ip_objetivo,
            ip_range=ip_range
        )
        
    def arp(self):
        print(self.colors.POINTGREEN("Iniciando el escaneo ARP"))
        print(self.my_ip)

    def dir(self):
        print(self.__dir__())

