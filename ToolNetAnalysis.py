from Colors.colors import COLOR
from scan import Scan
from other import ListIface

from argparse import ArgumentParser
from os import getuid
from sys import exit, argv
from random import randint

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
                                type=str
                            )
        parser.add_argument(
                                "--ip-range",     
                                help="identificador de la red junto a mascara de red. Ejemplo(192.168.1.1/24)", 
                                type=str
                            )
        parser.add_argument(
                                "--ip-objetivo",  
                                help="ip objetivo", 
                                type=str
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
                                help="usar una direccion para spoofear", 
                                type=str
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
        
        scan = Scan()
        
        if len(argv) <= 1:
            print(colors.POINTRED("Usted no introducio parametro alguno. Modo de uso:"))
            parser.print_help()   
            exit(0)
        
        parser = parser.parse_args()
        
        print(parser.ttl_packet_random)
        if parser.ttl_packet_random != None:
            ttl_random = {0:randint, 1:parser.ttl_packet_random}
        
        if parser.scan_mode_arp == True:
            scan.arp()
            scan.dir()
        
    else:
        print(colors.POINTRED("Usted no es un usuario con permisos de administrador"))
        exit(0)