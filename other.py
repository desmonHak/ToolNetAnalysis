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
            ip_range=None
        ) -> None:
    
        self.my_ip = ip
        self.my_mac = mac
        self.spoof_ip = spoof_ip
        self.spoof_mac = spoof_mac
        self.iface = iface
        
        self.ip_objetivo = ip_objetivo
        if self.Valid_IPv4(self.ip_objetivo) == False:
            raise self.ErrorIpFormat(self.ip_objetivo)
        
        self.ip_range = ip_range
        if self.Valid_IPv4("".join(self.ip_range.split("/"))) == False:
            raise self.ErrorIpRange(self.ip_range)
        
        self.ttl = ttl
        self.ttl_random = ttl_random
        self.ttl_random_status = False
        if ttl_random != None:
            self.ttl = self.ttl_random[1]
            self.ttl_random_status = True
        
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
        """.format(
            str(self.iface),
            str(self.my_ip), 
            str(self.my_mac), 
            str(self.spoof_ip),
            str(self.spoof_mac),
            str(self.ttl),
            str(self.ttl_random_status),
            str(self.ip_objetivo),
            str(self.ip_range)
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
        
