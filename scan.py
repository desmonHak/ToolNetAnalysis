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
            ip_range=None,
            verbose=False,
            timeout=None,
            count=1
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
            ip_range=ip_range,
            verbose=verbose,
            timeout=timeout,
            count=count
        )
        
    def arp(self):
        print(self.colors.POINTGREEN("Iniciando el escaneo ARP"))
        print(
            """
            Su tarjeta de red(NIC) es: {} 
            Su direcion IP: {}
            Su direccion MAC: {}
            Direccion IP a spoofear: {}
            IP rango objetivo = {}
            Modo verbose = {}
            Tiempo de espera(timeout) = {}
        """.format(
                self.iface,
                self.my_ip,
                self.my_mac,
                self.spoof_ip,
                self.ip_range,
                self.verbose,
                self.timeout
            )
        )
        
        
        lista_hosts = list()
        if self.spoof_ip != None:
            data = srp(
                        Ether(
                            dst="ff:ff:ff:ff:ff:ff"
                        ) / ARP(
                            pdst=self.ip_range, 
                            psrc=self.spoof_ip,
                        ), 
                        timeout=self.timeout, 
                        verbose=self.verbose, 
                        iface=self.iface
                    )[0]
        else:
            data = srp(
                        Ether(
                            dst="ff:ff:ff:ff:ff:ff"
                        ) / ARP(
                            pdst=self.ip_range, 
                            psrc=self.my_ip
                        ), 
                        timeout=self.timeout, 
                        verbose=self.verbose, 
                        iface=self.iface
                    )[0]

        if len(data) != 0:
            if self.verbose == True:
                data.rawhexdump()
            
            for host in data: 
                if self.verbose == True:
                    host[0].show2()
                    print("Payload: {}".format(host[0].payload))
                    host[1].show2()
                    print("Payload: {}".format(host[1].payload))
                lista_hosts.append([host[1].psrc, host[1].hwsrc])
                
            for numero_host in range(0,len(lista_hosts)): 
                if len(lista_hosts[numero_host]) == 0: lista_hosts.pop(numero_host)
                
            for host in lista_hosts:
                print(self.colors.POINTGREEN("Direcion IP:({}), direccion MAC:({})".format(host[0], host[1])))
                
            return lista_hosts
        else:
            print(self.colors.POINTRED("No se a encontrado ningun dispositivo, o ninguno respondio al 'Who has'"))
            return []

    def print_sniff(self, packet):
        packet.show2()
        packet.summary()
        packet.type
        
    def sniff(self):
        # store=False tells sniff() function to discard sniffed packets
        sniff(iface=self.iface, store=False, prn=self.print_sniff)

    def dir(self):
        print(self.__dir__())

