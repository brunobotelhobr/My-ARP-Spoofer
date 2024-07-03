# My-ARP-Spoofer
POC: Python implementation of Spoofing and Detection


This uses Python 3.
To install the requirements:
````
pip install -r requirements.txt
`````

## Attack
``````
python arpspoof.py --help 
usage: arpspoof.py [-h] [-no_routing] -i INTERFACE -t TARGET_ADDRESS -s SPOOF_ADDRESS

options:
  -h, --help         show this help message and exit
  -no_routing        [Optional] Disable automatic kernel routing enabler.
  -i INTERFACE       Interface to use on ARP attacks.
  -t TARGET_ADDRESS  Target Address or Network
  -s SPOOF_ADDRESS   Spoofed Address or Network
```````

Example:
````
python arpspoof.py -i eth0 -t 192.168.200.5 -s 192.168.200.2
````

## Monitoring
````
python arpspoof-monitor.py --help                                       
usage: arpspoof-monitor.py [-h] -i INTERFACE

options:
  -h, --help    show this help message and exit
  -i INTERFACE  Interface to use for ARP attacks detection.
`````

Example:
````
python arpspoof-monitor.py -i eth0
````                                      

