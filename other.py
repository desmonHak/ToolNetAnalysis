from Colors.colors import COLOR

from argparse import Action
from scapy.all import ifaces

class Options:
    
    def __init__(self,
            ip,
            mac,
            spoof_ip,
            spoof_mac,
            ttl,
            colors=COLOR()
        ) -> None:
    
        self.my_ip = ip
        self.my_mac = mac
        self.spoof_ip = spoof_ip
        self.spoof_mac = spoof_mac
        self.ttl = ttl

        self.colors = colors

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
        
