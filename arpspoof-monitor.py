#!/usr/bin/python
############################################################
# Requirements:
# pip install scapy
# pip install termcolor
############################################################
from termcolor import colored
import datetime
import argparse
import logging
import time
import os
from scapy.all import conf, sniff
from scapy.layers.l2 import ARP

# Disable scapy warning output
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

NAME = "Arp Spoofing Detector"
VERSION = "1.0"
DATE = "02/06/2024"
ARP_REPLY_LIST = []
ARP_ATTACKERS_LIST = []


def parse_arguments():
    """Parse and return arguments from the command line."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        required=True,
        action="store",
        dest="interface",
        help="Interface to use for ARP attacks detection.",
    )
    return parser.parse_args()


def print_banner():
    """Print the banner."""
    print("")
    print(f"### {NAME}")
    print(f"### Version {VERSION}")
    print(f"### Date {DATE}")
    print("### by Bruno Botelho - bruno.botelho.br@gmail.com")
    print("")


def log_timestamp():
    """Return the current timestamp."""
    return datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def arp_callback(pkt):
    """Callback function for ARP packets."""
    log = (
        log_timestamp()
        + " ARP Replay "
        + colored(pkt[ARP].psrc, "blue")
        + " is at "
        + colored(pkt[ARP].hwsrc, "blue")
    )
    mac = pkt[ARP].hwsrc
    ip = pkt[ARP].psrc
    register = [mac, ip]
    if (register) not in ARP_REPLY_LIST:
        print(log)
        ARP_REPLY_LIST.append(register)
        for i in ARP_REPLY_LIST:
            if i[1] == ip and i[0] != mac:
                if register not in ARP_ATTACKERS_LIST:
                    ARP_ATTACKERS_LIST.append(register)
                    print(
                        log_timestamp()
                        + " ARP Spoofing Detected "
                        + colored(ip, "red")
                        + " has multiple MACs: "
                        + colored(mac, "red")
                        + " and "
                        + colored(i[0], "red")
                    )
                    current_arps = os.popen("arp -a").read()
                    print(log_timestamp(), "Current ARP Table (arp -a):")
                    for l in current_arps.splitlines():
                        print("    " + l)


def arp_process(pkt):
    """Process ARP packets."""
    if ARP in pkt and pkt[ARP].op == 2:
        arp_callback(pkt)


def arp_mon():
    """Monitor ARP packets."""
    print("### Initiating ARP Spoofing Detection")
    print("### Interface " + conf.iface)
    print("")
    print(log_timestamp(), "Current ARP Table (arp -a):")
    current_arps = os.popen("arp -a").read()
    for l in current_arps.splitlines():
        print("    " + l)
    sniff(prn=arp_process, store=0)


def main():
    """Main function."""
    args = parse_arguments()
    print_banner()
    try:
        while True:
            arp_mon()
    except KeyboardInterrupt:
        print(f"{log_timestamp()} ARP Spoofing Detection stopped by user.")


if __name__ == "__main__":
    main()
