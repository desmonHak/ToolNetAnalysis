from Colors.colors import COLOR
from scan import Scan
from other import ListIface

from argparse import ArgumentParser
from os import getuid
from sys import exit, argv
from random import randint
from scapy.all import get_working_if, get_if_addr, get_if_hwaddr

if __name__ == "__main__":
    
    colors = COLOR()
    
    print(colors.CLEAR())
    if getuid() == 0:

        parser = ArgumentParser(
            prog = __doc__,

            description = """
                Esta es una herramienta de analisis y reconocimiento
            
            """,

            epilog="""
            """
        )
        
        parser.add_argument(
                                "--iface",        
                                help="especificar la interfaz", 
                                type=str,
                                default=get_working_if()
                            )
        parser.add_argument(
                                "--ip-range",     
                                help="identificador de la red junto a mascara de red. Ejemplo(192.168.1.1/24)", 
                                type=str,
                                default=None
                            )
        parser.add_argument(
                                "--ip-objetivo",  
                                help="ip objetivo", 
                                type=str,
                                default=None
                            )
        parser.add_argument(
                                "--ping-spoof",          
                                help="""
                                    realizar un ping spoofing. 
                                    <primer argumento = ip a suplantar, se 
                                    pueda usar la flag --ip-spoof para especificar este campo>, 
                                    <ip a donde enviar el paquete> <ttl del paquete, se aplica por defecto un ttl de 128>
                                """, 
                                type=str, 
                                nargs='+', 
                                default=None
                            )
        parser.add_argument(
                                "--ip-spoof",            
                                help="Usar una direccion IP para spoofear", 
                                type=str,
                                default=None,
                            )
        parser.add_argument(
                                "--mac-spoof",            
                                help="Usar una direccion MAC para spoofear", 
                                type=str,
                                default=None,
                            )
        parser.add_argument(
                                "--ttl-packet",          
                                help="ttl de los paquetes, por defecto se usa 128", 
                                type=int,
                                default=128
                            )
        parser.add_argument(
                                "--ttl-packet-random",   
                                help="""
                                    ttl aleatorio para los paquetes, se
                                    especifica el rango aleatorio para el 
                                    ttl en esta flag como --ttl-packet-random <rango inicial> <rango final>
                                """, 
                                type=int, 
                                default=None,
                                nargs=2
                            )
        parser.add_argument(
                                "--scan-tcp-random",     
                                help="escanea los puertos aleatorios de una red o dispositivo", 
                                action="store_true"
                            )
        parser.add_argument(    
                                "--scan-mode-arp",   
                                help="escanear la red con el protocolo ARP", 
                                action="store_true",
                                default=False
                            )
        parser.add_argument(
                                "--iface-list",          
                                help="listar interfaces", 
                                action=ListIface
                            )
        
        if len(argv) <= 1:
            print(colors.POINTRED("Usted no introducio parametro alguno. Modo de uso:"))
            parser.print_help()   
            exit(0)
        parser = parser.parse_args()

        
        if parser.ttl_packet_random != None:
            parser.ttl_packet_random = {0:randint, 1:parser.ttl_packet_random}
            
            
        scan = Scan(
            ttl=parser.ttl_packet,
            spoof_ip=parser.ip_spoof,
            spoof_mac=parser.mac_spoof,
            iface=parser.iface,
            ip=get_if_addr(parser.iface),
            mac=get_if_hwaddr(parser.iface),
            ttl_random=parser.ttl_packet_random,
            ip_objetivo=parser.ip_objetivo,
            ip_range=parser.ip_range
        )
        print(scan)
        
        if parser.scan_mode_arp == True:
            scan.arp()
            scan.dir()
        
    else:
        print(colors.POINTRED("Usted no es un usuario con permisos de administrador"))
        exit(0)