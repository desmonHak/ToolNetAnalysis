from Colors.colors import COLOR

from argparse import Action
from scapy.all import ifaces

class Options(object):
    
    class ErrorIpRange(Exception):
        def __init__(self, ip_range, colors=COLOR(), msg="Este rango IP ({}) no es valida, debe introducir algo similar a esto -> 192.168.1.1/24"):
            self.ip_range = ip_range
            self.msg = msg.format(ip_range)
            super().__init__(colors.POINTRED("\n"+self.msg))
            
    class ErrorIpFormat(Exception):
        def __init__(self, ip_range, colors=COLOR(), msg="Esta direccion IP ({}) no es valida, debe introducir algo similar a esto -> 192.168.1.1"):
            self.ip_range = ip_range
            self.msg = msg.format(ip_range)
            super().__init__(colors.POINTRED("\n"+self.msg))
            
    def __init__(self,
            ip=None,
            mac=None,
            spoof_ip=None,
            spoof_mac=None,
            ttl=None,
            iface=None,
            ttl_random=None,
            colors=COLOR(),
            ip_objetivo=None,
            ip_range=None,
            verbose=False,
            timeout=None,
            count=1
        ) -> None:
    
        self.my_ip = ip
        self.my_mac = mac
        self.spoof_mac = spoof_mac
        self.iface = iface
        self.timeout = timeout
        
        self.ip_objetivo = ip_objetivo
        if self.ip_objetivo != None:
            if self.Valid_IPv4(self.ip_objetivo) == False:
                raise self.ErrorIpFormat(self.ip_objetivo)
        
        self.spoof_ip = spoof_ip
        if self.spoof_ip != None:
            if self.Valid_IPv4(self.spoof_ip) == False:
                raise self.ErrorIpFormat(self.spoof_ip)
        
        self.ip_range = ip_range
        if self.ip_range != None:
            if self.Valid_IPv4(self.ip_range.split("/")[0]) == False:
                raise self.ErrorIpRange(self.ip_range)
        
        self.ttl = ttl
        self.ttl_random = ttl_random
        self.ttl_random_status = False
        if ttl_random != None:
            self.ttl = self.ttl_random[1]
            self.ttl_random_status = True
        
        self.verbose = verbose
        self.count = count
        self.colors = colors
            
    def Valid_IPv4(self, ip_direccion):
        ip_direccion = ip_direccion.split(".")
        if len(ip_direccion) != 4: return False
        for octeto in ip_direccion:
            if int(octeto) > 255 or int(octeto) < 0: return False
        return True
        
    def __str__(self):
        return """
            Su tarjeta de red(NIC) es: {} 
            Su direcion IP: {}
            Su direccion MAC: {}
            Direccion IP a spoofear: {}
            Direccion MAC a spoofear: {}
            TTL a usar = {}
            TTL aleatorio = {}
            IP objetivo = {}
            IP rango objetivo = {}
            Modo verbose = {}
            Tiempo de espera(timeout) = {}
            Count = {}
        """.format(
            self.iface,
            self.my_ip,
            self.my_mac,
            self.spoof_ip,
            self.spoof_mac,
            self.ttl,
            self.ttl_random_status,
            self.ip_objetivo,
            self.ip_range,
            self.verbose,
            self.timeout,
            self.count
        )
    

class ListIface(Action):

    def __init__(
                    self, 
                    option_strings, 
                    dest, 
                    nargs=0, 
                    type=None,
                    help=None,
                    required=False,
                    default=None,
                    metavar=None,
                    **kwargs
                ):
        #if nargs is not None:
        #    raise ValueError("nargs not allowed")
        #super().__init__(option_strings, dest, **kwargs)
        super(ListIface, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            default=default,
            required=required,
            metavar=metavar,
            type=type,
            help=help
        )

    def __call__(self, parser, namespace, values, option_string=None):
        print(ifaces)
        setattr(namespace, self.dest, values)
        
