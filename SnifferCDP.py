#Import system modules
#os.system(r"C:\Users\gdlvgonz\Desktop\CDP\npcap.exe")
os.system(r".\npcap.exe")
import scapy
from scapy.all import *
from scapy.utils import *
from scapy.utils import hexdump
from scapy.all import sniff
from scapy.layers.l2 import Dot3, LLC, SNAP
import sys, string, os
import subprocess
import time
import struct
from scapy.all import IFACES
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import checksum
from scapy.layers.l2 import SNAP
from scapy.compat import orb, chb
from scapy.config import conf
from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPMsgPortID, CDPv2_HDR
from scapy.fields import ByteEnumField, ByteField, FieldLenField, FlagsField, \
    IP6Field, IPField, PacketListField, ShortField, StrLenField, \
    X3BytesField, XByteField, XShortEnumField, XShortField
from subprocess import Popen,PIPE,STDOUT,call


conf.use_pcap = True
#list_contrib()
load_contrib("cdp")

print("SnifferCDP.py - Execute process location")
print("Copyright (C) 2020 VAGR - Telecom Team GDL")

def cdp_monitor_callback(pkt):   
    print("Ejecutando método cdp_monitor_callback")
    #print(pkt.summary())                            #802.3 00:da:55:77:5b:22 > 01:00:0c:cc:cc:cc / LLC / SNAP / CDPv2_HDR
    #print(pkt[LLC].summary())                       #LLC / SNAP / CDPv2_HDR
    #pkt[LLC].show()                                 #Show all packet in columns
    #print(pkt[SNAP].summary())                      #SNAP / CDPv2_HDR
    #print(pkt[CDPv2_HDR].summary())                 #CDPv2_HDR
    pkt[CDPv2_HDR].fields["msg"]
    #pkt[Raw].fields
    hexdump(pkt)                                     #Show information in Hexadecimal
    #hexdump(raw)                                    #Show information in Hexadecimal
    #e = pkt[Raw].fields   
    print("Deciphering...")     
    time.sleep(2)        
    
    #pkt.command()    
    #pkt.show(dump = True)    
    #string = pkt.show(dump = True)    
    #print(string)
    #pkt.display()       

    #miDevice = open("miDevice.txt", "w")
    #miDevice.write(string)
    #miDevice.close()       
         

    hostname = pkt["CDPMsgDeviceID"].val.decode('utf-8')
    ip = pkt["CDPAddrRecordIPv4"].addr
    interface = pkt["CDPMsgPortID"].iface.decode('utf-8')       
    conjunto = "Hostname: "+ hostname + " IP: " + ip + " PortID: " + interface
    print(conjunto)
    
   
    miDevice = open("miDevice.txt", "w")
    miDevice.write(conjunto)
    miDevice.close()    
    
    time.sleep(50)   
  

interface = 'Ethernet'
capturefilter = 'ether dst 01:00:0c:cc:cc:cc'

#print(interface)
#print(capturefilter)

#show_interfaces()
#IFACES.data

#os.system("netsh interface show interface Ethernet")
#state = subprocess.call("netsh interface show interface Ethernet")


proc = Popen('netsh interface show interface Ethernet', shell = True, stdout = PIPE, )
output = proc.communicate()[0]
#print (output) 




miNIC = open("miNIC.txt", "w")
miNIC.write(str(output))
miNIC.close() 


with open("miNIC.txt") as f:
    text = f.readlines()
    size = len(text)
    
    for line in text:

        if "Disconnected" in line:
            print("Tu tarjeta Ethernet esta deconectada")
            time.sleep(10)
            sys.exit(0)
        if "Connected" in line:
            print("Tu tarjeta Ethernet esta conectada")


#iface = input("Enter the interface to sniff on: ")
p = sniff(prn = cdp_monitor_callback, iface = interface,  filter = capturefilter,  count = 1)
