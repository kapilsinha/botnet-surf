'''
Intro to this package is on https://pypi.python.org/pypi/pypcapfile
'''
import os
from distutils.core import setup
import sys
from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip
import binascii
import ctypes
import bisect

def open_pcap_file(fname):
    try:
        return open(os.path.join(os.path.dirname(__file__), fname))
    except Exception:
        print('Invalid or missing pcap file')
        sys.exit(1)

'''
print type(capfile.packets[0])
# <class 'pcapfile.structs.pcap_packet'>
print type(capfile.packets[0].packet)
# <class 'pcapfile.protocols.linklayer.ethernet.Ethernet'>
print type(capfile.packets[0].header)
# <class 'pcapfile.structs.LP___pcap_header__'>
print type(capfile.packets[0].timestamp) # <type 'long'>
print type(capfile.packets[0].timestamp_us) # <type 'long'>

# These appear to be the same and are payload size + 34 bytes
print type(capfile.packets[0].capture_len) # <type 'long'>
print type(capfile.packets[0].packet_len) # <type 'long'>

# This is the Ethernet Hardware Address
print type(capfile.packets[0].packet.src) # <type 'str'>
print type(capfile.packets[0].packet.dst) # <type 'str'>

# This is the EtherType - 0x800 = 2048 is IPv4
print type(capfile.packets[0].packet.type) # <type 'int'>

# Example string:
# ipv4 packet from 147.32.84.165 to 147.32.84.255 carrying 76 bytes
print type(capfile.packets[0].packet.payload) # <type 'str'>
or <class 'pcapfile.protocols.network.ip.IP'>
'''

FILENAME = sys.argv[1]
LAYERS = 2 # chose this arbitrarily based on documentation

# Open file and initialize variables
testcap = open_pcap_file(FILENAME)
capfile = savefile.load_savefile(testcap, layers=2)

if not capfile.valid:
    print('Invalid packet capture')
    sys.exit(1)
    
print 'Opened', FILENAME
edges = [] # list of tuples of the form
# (ip_source, ip_dest, timestamp, timestamp_us, num_bytes)
nodes = ['Z'] # list of unique IP addresses
# The 'Z' is a temporary placeholder - ugly but it's use to allow us
# to do binary searches of the nodes array
total_packets = 0
not_ipv4_packets = 0
# We will not include non-ipv4 packet transfers in our graph since we
# can't access its information well using pycapfile - moreover many of them
# are in ARP, which isn't very relevant to us
earliest_timestamp = None
latest_timestamp = None

# Iterate over all the packets and update the following:
# total_packets, not_ipv4_packets, edges, nodes, 
# earliest_timestamp, latest_timestamp

# CONSIDER COMBINING CONSECUTIVE PACKETS IF THEY HAVE THE SAME SOURCE
# AND DESTINATION ADDRESSES AND HAVE A TIME RANGE. THIS CAN CUT DOWN ON
# NUMBER OF EDGES
for i in range(len(capfile.packets)):
    total_packets += 1
    if capfile.packets[i].packet.type != 2048: # if EtherType is not IPv4
        not_ipv4_packets += 1
        continue

    timestamp = capfile.packets[i].timestamp
    timestamp_us = capfile.packets[i].timestamp_us
    # Note that I don't account for timestamp_us below; we likely won't
    # need the precision
    if (earliest_timestamp is None or earliest_timestamp > timestamp):
        earliest_timestamp = timestamp
    if (latest_timestamp is None or latest_timestamp < timestamp):
        latest_timestamp = timestamp
    ''' # Uglier string processing technique
    payload_lst = str(capfile.packets[i].packet.payload).split()
    ip_source = payload_lst[3]
    ip_dest = payload_lst[5]
    num_bytes = int(payload_lst[7])
    '''
    ip_source = capfile.packets[i].packet.payload.src
    ip_dest = capfile.packets[i].packet.payload.dst
    num_bytes = len(capfile.packets[i].packet.payload.payload) // 2

    ''' # Cleaner code but perhaps less efficient
    if ip_source not in nodes:
        nodes.append(ip_source)
    if ip_dest not in nodes:
        nodes.append(ip_dest)
    '''
    j = bisect.bisect_left(nodes, ip_source)
    if nodes[j] != ip_source:
        nodes.insert(j, ip_source)
    j = bisect.bisect_left(nodes, ip_dest)
    if nodes[j] != ip_dest:
        nodes.insert(j, ip_dest)
    edges.append((ip_source, ip_dest, timestamp, timestamp_us, num_bytes))
del nodes[-1]
print total_packets
print not_ipv4_packets
#print edges
print nodes
print earliest_timestamp
print latest_timestamp
