from scapy.all import *
import re
import requests

captureInterface = "eth0"
captureFilter = "port 67"
requestURL = 'https://api.fingerbank.org/api/v2/combinations/interrogate?key=a259f73be9751dbccdbadbf0e5981696c365b042'
requestHeader = "Content-Type: application/json"

def procdhcp(pkt):
    print(pkt['Ethernet'].src)
    print(pkt['IP'].src)
    print(pkt['DHCP'].options)
    print(re.sub(r".*param_req_list', \[(.*?)\].*",r'\1',str(pkt['DHCP'].options)))
    dhcpParameters = re.sub(r".*param_req_list', \[(.*?)\].*",r'\1',str(pkt['DHCP'].options)).replace(' ','')

    requestParameters = {'"dhcp_fingerprint":"' + dhcpParameters + '","dhcp_vendor":"dhcpcd-5.5.6"'}

    result = requests.get(url = requestURL, params = requestParameters, headers = requestHeader)

    print(result.response())




pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procdhcp, store=0)