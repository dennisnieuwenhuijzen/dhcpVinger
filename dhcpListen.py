from scapy import *

captureInterface = "eth0"
captureFilter = "port 67"

def procdhcp(pkt):
    pkt.show()

pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procdhcp, store=0)