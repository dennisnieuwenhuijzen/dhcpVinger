from scapy.all import *
import re
import requests
import json
import pika

captureInterface = "eth0"
captureFilter = "tcp port 80"


class vingerResult():

    def __init__(self):
        self.mac = ''
        self.fingerprint = ''
        self.device = ''
        self.deviceName = ''
        self.manufacturer = ''
        self.operatingSystem = ''

def GET_print(pkt):
    r = "***************************************GET PACKET****************************************************\n"
    r += "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    r += "*****************************************************************************************************\n"
    return r

def prochttp(pkt):
    print(pkt['IP'].src)
    if pkt.find('GET'):
        return GET_print(pkt)

#    connection = pika.BlockingConnection(
#    pika.ConnectionParameters(host='172.19.12.14'))
#    channel = connection.channel()
#
#    channel.queue_declare(queue='endpointQ')
#
#    body = json.dumps(vingerObject.__dict__)
#
#    channel.basic_publish(exchange='', routing_key='endpointQ', body=body)
#    connection.close()
#
#



pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=prochttp, store=0)
