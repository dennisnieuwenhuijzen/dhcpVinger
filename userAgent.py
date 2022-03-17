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

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1

def prochttp(pkt):
    print(pkt['IP'].src)

    for layer in get_packet_layers(pkt):
        print (layer.name)

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
