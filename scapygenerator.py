#!/usr/bin/python
from scapy.all import *
from random import randint
import random
import string
import sys
import os

from scapy.packet import Packet,bind_layers
from scapy.fields import BitField,ByteField
from scapy.layers.l2 import Ether

def data_pack( len_datafield ):
    l = 0
    data_field = ''
    while l < len_datafield:
        data_field = data_field + random.choice(string.ascii_letters)
        l=l+1

    return data_field

VLAN_ID_0 = 0x81
VLAN_ID_1 = 0x00
IP_ID_0 = 0x08
IP_ID_1 = 0x00
MPLS_ID_0 = 0x88
MPLS_ID_1 = 0x47
QINQ_ID_0 = 0x88
QINQ_ID_1 = 0xA8
VNTAG_ID_0 = 0x89
VNTAG_ID_1 = 0x26

class MPLS(Packet):
    name = "MPLS"
    fields_desc =  [
        BitField("label", 3, 20),
        BitField("experimental_bits", 0, 3),
        BitField("bottom_of_label_stack", 1, 1), # Now we're at the bottom
        ByteField("TTL", 255)
    ]
bind_layers(Ether, MPLS, type = 0x8847) # Marks MPLS
bind_layers(MPLS, MPLS, bottom_of_label_stack = 0) # We're not at the bottom yet
bind_layers(MPLS, IP)

class VNTAG(Packet):
    name = "VNTAG"
    fields_desc =  [
        BitField("destination_bit", 0, 1 ),# Indicates which direction the frame is flowing.
        BitField("pointer_bit",     0, 1 ),
        BitField("destination_vif", 0, 14),# Identifies the destination port.
        BitField("looped",          0, 1 ),# Identifies the source vNIC, ment to identify multicast frames to ensure it is not forwarded back to where it originated.
        BitField("reserved",        0, 3 ),# For future use.
        BitField("source_vif",      0, 12),# vif_id of the downstream port.
        ByteField("next_field1",    0), # This is a field of type after VNTAG. If you need VLAN - enter next_field1=129(hex - 81)  next_field2=0(hex - 00)
        ByteField("next_field2",    0)  #
    ]
bind_layers(Ether, VNTAG, type = 0x8926) # Marks VNTAG

class QinQ(Packet):
    name = "QinQ"
    fields_desc =  [
        BitField("priority",         0, 3 ),
        BitField("dei_bit",          0, 1 ),
        BitField("id",               0, 12),
        ByteField("next_field1_qinq",    0), # This is a field of type after QinQ. If you need VLAN - enter next_field1=129(hex - 81)  next_field2=0(hex - 00)
        ByteField("next_field2_qinq",    0)  #
    ]
bind_layers(Ether, QinQ, type = 0x88A8) # Marks QinQ

count_packets=10
len_data_packets=20
packets=[]
mac_src = '01:02:03:04:05:06'
mac_dst = '07:08:09:0A:0B:0C'
data_pac = ''

list_of_parameter=sys.argv[1:]
command_execute = 'packets.append(Ether(src = mac_src,dst = mac_dst)/'

i=0
mpls_count=0
while i<len(list_of_parameter):
    if (list_of_parameter[i]=='mpls'):
        mpls_count=mpls_count+1
    i=i+1

i=0
id1=''
id2=''
   
i=0
while i<len(list_of_parameter):
    if i<(len(list_of_parameter)-1):
        if (list_of_parameter[i+1]=='ipv4'):
            id0='IP_ID_0'
            id1='IP_ID_1'
        if (list_of_parameter[i+1]=='vlan'):
            id0='VLAN_ID_0'
            id1='VLAN_ID_1'
        if (list_of_parameter[i+1]=='vntag'):
            id0='VNTAG_ID_0'
            id1='VNTAG_ID_1'
        if (list_of_parameter[i+1]=='qinq'):
            id0='QINQ_ID_0'
            id1='QINQ_ID_1'
        if (list_of_parameter[i+1]=='mpls'):
            id0='MPLS_ID_0'
            id1='MPLS_ID_1'

    if (list_of_parameter[i]=='ipv4'):
        command_execute = command_execute + 'IP(src=srcipv4,dst=dstipv4)/'
    if (list_of_parameter[i]=='udp'):
        command_execute = command_execute + 'UDP(sport=srcport,dport=dstport)/'
    if (list_of_parameter[i]=='vlan'):
        command_execute = command_execute + 'Dot1Q(vlan=vlanid)/'
    if (list_of_parameter[i]=='vntag'):
        command_execute = command_execute + 'VNTAG(next_field1='+id0+', next_field2='+id1+')/'
    if (list_of_parameter[i]=='qinq'):
        command_execute = command_execute + 'QinQ(id = vlanid,next_field1_qinq='+id0+', next_field2_qinq='+id1+')/'
    if (list_of_parameter[i]=='mpls'):
        if (mpls_count==1):
            command_execute = command_execute + 'MPLS(label = 255, bottom_of_label_stack =1, TTL = 255)/'
        else:
            command_execute = command_execute + 'MPLS(label = 255, bottom_of_label_stack =0, TTL = 255)/'            
        mpls_count=mpls_count-1

    i=i+1

command_execute = command_execute + 'data_pack(len_data_packets))'
print 'command execute:', str(command_execute)

p=0
while p < count_packets:
    p=p+1
    srcipv4   = "192.168."+str(p/256)   +"."+str(p%256)
    dstipv4   = "192.168."+str(10+p/256)+"."+str(p%256)
    srcport = p%256
    dstport = 256+p%256
    vlanid  = p%100+1
    exec(command_execute)

wrpcap("out.pcap", packets)
