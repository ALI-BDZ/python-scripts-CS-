from scapy.all import *

sniff(prn=lambda p: p.summary(), filter="ip or tcp")