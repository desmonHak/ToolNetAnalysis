from other import Options
from scapy.all import *

class Spoof(Options):
    
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
        super(Spoof,self).__init__(
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
            count=count,
        )
        
    def ping_spoofing(self):
        for i in range(0, self.count):
            
            if self.spoof_ip != None:
                ip_org = self.spoof_ip
            else:
                ip_org = self.my_ip
                
            if self.ttl_random_status == False:
                ttl = self.ttl
            else:
                ttl=self.ttl_random[0](
                                        self.ttl_random[1][0], 
                                        self.ttl_random[1][1]
                                    )
            print(
                """
                TTL del ICMP = {}
                IP objetivo = {}
                IP de origen = {}
                Modo verbose = {}
                Tiempo de espera(timeout) = {}
            """.format(
                    ttl,
                    self.ip_objetivo,
                    ip_org,
                    self.verbose,
                    self.timeout,
                )
            )
            
            paquete = IP(
                            src=ip_org, 
                            dst=self.ip_objetivo, 
                            ttl=ttl
                            )/ICMP()
            
            if self.verbose == True:
                paquete.show2()
                
            #send(paquete)
            paquete = sr(paquete, timeout=self.timeout, verbose=self.verbose)
            if not (paquete is None):
                for paquete_send in paquete[0]:
                    paquete_send[0].show2()
                    paquete_send[1].show2()
                for paquete_send in paquete[1]:
                    paquete_send[0].show2()
                    paquete_send[1].show2()

    def dir(self):
        print(self.__dir__())

