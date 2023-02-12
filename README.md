# ToolNetAnalysis

----

Herramienta de analisis en red.

----
# Parametros
```Python
usage: ToolNetAnalysis.py [-h] [-if--iface IF__IFACE] [--verbose]
                          [-ip-r--ip-range IP_R__IP_RANGE]
                          [--ip-objetivo IP_OBJETIVO] [--ping-spoof]
                          [--ip-spoof IP_SPOOF] [--mac-spoof MAC_SPOOF]
                          [--timeout TIMEOUT] [--ttl-packet TTL_PACKET]
                          [--ttl-packet-random TTL_PACKET_RANDOM TTL_PACKET_RANDOM]
                          [--count COUNT] [--scan-tcp-random] [--scan-mode-arp]
                          [--iface-list] [--sniff]

Esta es una herramienta de analisis y reconocimiento

options:
  -h, --help            show this help message and exit
  -if--iface IF__IFACE  Especificar la tarjeta de red con la que operar
  --verbose, -v         El modo verbose muestra informacion de los procesos
                        internos
  -ip-r--ip-range IP_R__IP_RANGE
                        Rango de red objetivo junto a mascara de red.
                        Ejemplo(192.168.1.1/24)
  --ip-objetivo IP_OBJETIVO, -ip-obj IP_OBJETIVO
                        IP objetivo a la que realizar el ataque o analizar
  --ping-spoof, -ping-sp
                        Realizar un ping spoofing. Se puede especificar el ttl o
                        usar ttl aleatorio. Se a de especificar la IP de
                        destino(Objetivo). Opcionalmente se puede especificar la
                        IP de origen. Se puede spoofear la direccion IP de
                        origen con --ip-spoof
  --ip-spoof IP_SPOOF, -ip-sp IP_SPOOF
                        En este campo se puede especificar la direccion IP a
                        spoofear
  --mac-spoof MAC_SPOOF, -mac-sp MAC_SPOOF
                        En este campos se puede especidiar la direccion MAC que
                        se usara para spoofear
  --timeout TIMEOUT, -t TIMEOUT
                        tiempo de espera para le escucha de paquetes.
  --ttl-packet TTL_PACKET, -ttl TTL_PACKET
                        En este campo se puede especificar el ttl de los
                        paquetes, por defecto se usa 128
  --ttl-packet-random TTL_PACKET_RANDOM TTL_PACKET_RANDOM, -ttl-rand TTL_PACKET_RANDOM TTL_PACKET_RANDOM
                        Esta flag especifica que se usara ttl aleatorio para los
                        paquetes. Se a de especifica el rango aleatorio para el
                        ttl en esta flag de la siguiente manera --ttl-packet-
                        random <rango inicial> <rango final>
  --count COUNT, -c COUNT
                        Esta flag permite especificar el count, por ejemplo. En
                        icmp spoof, usando count 5 se puede realizar 5
                        peticiones ICMP spoofeadas. Por defecto count vale 1.
  --scan-tcp-random, -sc-tcp-rand
                        Escanea los puertos aleatorios de una red o dispositivo
  --scan-mode-arp, -sc-arp
                        Escanear la red haciendo uso del protocolo ARP
  --iface-list, -if-list
                        Listar interfaces las interfaces de red del dispositivo
                        en el que se esta trabajando
  --sniff, -sn          Sniffear la red. Puede usar --iface para especificar que
                        tarjeta usar para realizar el sniffing


```
----
# Instalacion
```batch
pip install -r requirements.txt
```

----
# Uso

* Mostrar ayuda:
```batch
sudo python ToolNetAnalysis.py -h 
```

* Ejemplo de escaneo de red con protocolo ARP:
`--scan-mode-arp` especifica que se quiere hacer una escaneo usando el protocolo ARP.
`--ip-objetivo` es la puerta de enlace en este caso, comunmente un router.
`--ip-range 192.168.1.0/24` es el rango de red a analizar, se le especificar con el identificador de red y la mascara de red en este caso. Aqui escanea de `192.168.1.1 - 192.168.1.254` debido a la mascara de red `24` que corresponde a `255.255.255.0`.
`--ip-spoof 192.168.1.2` es la direccion IP a la que suplantar, en este caso la `192.168.1.2`. `-v` nos pone el modo verbose el cual nos da mas informacion sobre el proceso. `--timeout 2` pone un tiempo de espera de 2 segundos.

```batch
sudo python ToolNetAnalysis.py --scan-mode-arp --ip-objetivo 192.168.1.1 --ip-range 192.168.1.0/24 -v --ip-spoof 192.168.1.2 --timeout 2
```
 
* Ejemplo de Ping spoof:
`--ping-spoof` especifica que se realizara un ping o un ping spoof.
`--ip-spoof 192.168.1.129` permite especificar la IP de origen, en este caso puede ser nuestra direccion IP local en la red si queremos realizar un ping legitimo, en este caso, si existe el dispositivo reciviremos respuesta, es importante usar `--timeout` y especificar el tiempo de espera, o se quedara ahi hasta que reciba respuesta, la cual si el dispositivo no existe o tiene un firewallm nunca recibira dicha. En el caso de que pongamos una direccion IP de otro dispositivo realizando el spoofing, necesitamos especificar la direcion IP y usar `--timeout` ya que la respuesta de no se nos sera enviada, se enviara al dispositivo sppofeado. Podemos comprobar si los datos llegan con `--sniff`.
`--ip-objetivo` es la direccion IP a la que enviar el PING y del cual podemos o no esperar su respuesta.
`--ttl-packet-random` esta flag permite hacer que el `ttl` de los paquete icmp sea aleatorio en cada envio. Se le pasa dos args el cual corresponde al rango de valores aleatorios que se usaera para generar los numeros aleatorios.
`--count` especifica que se envia 5 paquetes ICMP al objetivo.
`--timeout` es el tiempo de espera para los paquetes enviados. Es importante especificar el tiempo, o se quedara esperando el paquete por siempre, lo cual puede no llegar a ser nunca.

```batch
sudo python ToolNetAnalysis.py --ping-spoof --ip-spoof 192.168.1.129 --ip-objetivo 192.168.1.1 --ttl-packet-random 1 255 --count 5 --timeout 2
```

* Ejemplo de sniffing:
`--sniff` especifica que se quiere realizar un sniffeo.
`--iface` especifica la interfaz con la cual realizar el sniffeo. Esta es opcional.
```batch
sudo python ToolNetAnalysis.py --sniff --iface wlan0
```

* Listar interfaces:
`--iface-list` permite listar las interfaces
```batch
sudo python ToolNetAnalysis.py --iface-list 
```

----
