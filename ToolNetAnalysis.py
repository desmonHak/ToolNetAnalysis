from Colors.colors import COLOR
from scan import Scan
from other import ListIface

from argparse import ArgumentParser
from os import getuid
from sys import exit, argv
from random import randint
from scapy.all import get_working_if, get_if_addr, get_if_hwaddr, conf, BrightTheme

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
                                help="Especificar la tarjeta de red con la que operar", 
                                type=str,
                                default=get_working_if()
                            )
        parser.add_argument(
                                "--verbose",        
                                "-v",
                                help="El modo verbose muestra informacion de los procesos internos", 
                                action="store_true",
                                default=False
                            )
        parser.add_argument(
                                "--ip-range",     
                                help="Rango de red objetivo junto a mascara de red. Ejemplo(192.168.1.1/24)", 
                                type=str,
                                default=None
                            )
        parser.add_argument(
                                "--ip-objetivo",  
                                help="IP objetivo a la que realizar el ataque o analizar", 
                                type=str,
                                default=None
                            )
        parser.add_argument(
                                "--ping-spoof",          
                                help="""
                                    Realizar un ping spoofing. Se puede especificar el ttl o usar ttl aleatorio. Se a de
                                    especificar la IP de destino(Objetivo). Opcionalmente se puede especificar la IP de
                                    origen. Se puede spoofear la direccion IP de origen con --ip-spoof
                                """, 
                                type=str, 
                                nargs='+', 
                                default=None
                            )
        parser.add_argument(
                                "--ip-spoof",            
                                help="En este campo se puede especificar la direccion IP a spoofear", 
                                type=str,
                                default=None,
                            )
        parser.add_argument(
                                "--mac-spoof",            
                                help="En este campos se puede especidiar la direccion MAC que se usara para spoofear", 
                                type=str,
                                default=None,
                            )
        parser.add_argument(
                                "--timeout",          
                                help="tiempo de espera para le escucha de paquetes.", 
                                type=int,
                                default=None
                            )
        parser.add_argument(
                                "--ttl-packet",          
                                help="En este campo se puede especificar el ttl de los paquetes, por defecto se usa 128", 
                                type=int,
                                default=128
                            )
        parser.add_argument(
                                "--ttl-packet-random",   
                                help="""
                                    Esta flag especifica que se usara ttl aleatorio para los paquetes. Se
                                    a de especifica el rango aleatorio para el ttl en esta flag de la siguiente manera
                                    \n--ttl-packet-random <rango inicial> <rango final>
                                """, 
                                type=int, 
                                default=None,
                                nargs=2
                            )
        parser.add_argument(
                                "--scan-tcp-random",     
                                help="Escanea los puertos aleatorios de una red o dispositivo", 
                                action="store_true"
                            )
        parser.add_argument(    
                                "--scan-mode-arp",   
                                help="Escanear la red haciendo uso del protocolo ARP", 
                                action="store_true",
                                default=False
                            )
        parser.add_argument(
                                "--iface-list",          
                                help="Listar interfaces las interfaces de red del dispositivo en el que se esta trabajando", 
                                action=ListIface
                            )
        parser.add_argument(    
                                "--sniff",   
                                help="Sniffear la red", 
                                action="store_true",
                                default=False
                            )
        if len(argv) <= 1:
            print(colors.POINTRED("Usted no introducio parametro alguno. Modo de uso:"))
            parser.print_help()   
            exit(0)
        parser = parser.parse_args()

        
        if parser.ttl_packet_random != None:
            parser.ttl_packet_random = {0:randint, 1:parser.ttl_packet_random}
            

        conf.color_theme = BrightTheme()

        scan = Scan(
            ttl=parser.ttl_packet,
            spoof_ip=parser.ip_spoof,
            spoof_mac=parser.mac_spoof,
            iface=parser.iface,
            ip=get_if_addr(parser.iface),
            mac=get_if_hwaddr(parser.iface),
            ttl_random=parser.ttl_packet_random,
            ip_objetivo=parser.ip_objetivo,
            ip_range=parser.ip_range,
            verbose=parser.verbose,
            timeout=parser.timeout
        )
        print(scan)
        
        if parser.scan_mode_arp == True:
            scan.arp()
        
        if parser.sniff == True:
            scan.sniff()
    else:
        print(colors.POINTRED("Usted no es un usuario con permisos de administrador"))
        exit(0)