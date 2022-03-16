from scapy.all import *
import re
import requests
import json
import pika

captureInterface = "wlan0"
captureFilter = "port 67"
requestURL = 'https://api.fingerbank.org/api/v2/combinations/interrogate?key=a259f73be9751dbccdbadbf0e5981696c365b042'
requestHeader = { 'Content-Type': 'application/json' }
requestParameters = {}

class vingerResult():

    def __init__(self):
        self.mac = ''
        self.fingerprint = ''
        self.device = ''
        self.deviceName = ''
        self.manufacturer = ''
        self.operatingSystem = ''


def procdhcp(pkt):
    print(pkt['Ethernet'].src)
    print(pkt['IP'].src)
    print(pkt['DHCP'].options)
    print(re.sub(r".*param_req_list', \[(.*?)\].*",r'\1',str(pkt['DHCP'].options)))
    dhcpParameters = re.sub(r".*param_req_list', \[(.*?)\].*",r'\1',str(pkt['DHCP'].options)).replace(' ','')

    requestParameters['dhcp_fingerprint'] = dhcpParameters

    print(requestParameters)

    result = requests.get(requestURL, params = requestParameters, headers = requestHeader)
    data = dict(result.json())
    
    #print('Device: ' + data['device'].get('name'))
    #print('Device name: ' + data['manufacturer'].get('name'))
    #print('OS: ' + data['operating_system'].get('name'))

    print(json.dumps(data, indent = 2))
    print('')
    print('Result:')
    print('- ' + pkt['Ethernet'].src)
    vingerObject = vingerResult()
    try:
        vingerObject.mac = pkt['Ethernet'].src.replace(':','')
    except:
        pass
    try:
        vingerObject.fingerprint = requestParameters['dhcp_fingerprint']
    except:
        pass
    try:
        vingerObject.device = data['device'].get('name')
    except:
        pass
    try:
        vingerObject.deviceName = data['device_name']
    except:
        pass
    try:
        vingerObject.manufacturer = data['manufacturer'].get('name')
    except:
        pass
    try:
        vingerObject.operatingSystem = data['operating_system'].get('name')
    except:
        pass
    print(vingerObject.__dict__)


    connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='172.19.12.14'))
    channel = connection.channel()

    channel.queue_declare(queue='endpointQ')

    body = json.dumps(vingerObject.__dict__)

    channel.basic_publish(exchange='', routing_key='endpointQ', body=body)
    connection.close()





pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procdhcp, store=0)
