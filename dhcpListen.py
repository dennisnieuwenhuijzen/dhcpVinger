from scapy.all import *

captureInterface = "eth0"
captureFilter = "port 67"

def procdhcp(pkt):
    print(pkt['Ethernet'].src)
    print(pkt['IP'].src)
    print(pkt['DHCP'].options)
    print(re.sub(r".*param_req_list', \[(.*?)\].*",r'\1',pkt['DHCP'].options))

pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procdhcp, store=0)