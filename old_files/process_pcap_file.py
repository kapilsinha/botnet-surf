'''
Intro to this package is on https://pypi.python.org/pypi/pypcapfile
NOTE: This program will combine consecutive packets between two nodes
to simplify the final graph

Types of variables in the package:
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

import os
import sys
from pcapfile import savefile
#from pcapfile.protocols.linklayer import ethernet
#from pcapfile.protocols.network import ip
import bisect

class PcapFile:
    def __init__(self, total_packets, not_ipv4_packets, edges, \
        nodes, earliest_timestamp, latest_timestamp):
        self.total_packets = total_packets
        self.not_ipv4_packets = not_ipv4_packets
        self.edges = edges
        self.nodes = nodes
        self.earliest_timestamp = earliest_timestamp
        self.latest_timestamp = latest_timestamp

    def get_total_packets(self):
        return self.total_packets

    def get_not_ipv4_packets(self):
        return self.not_ipv4_packets

    def get_edges(self):
        return self.edges

    def get_nodes(self):
        return self.nodes

    def get_earliest_timestamp(self):
        return self.earliest_timestamp

    def get_latest_timestamp(self):
        return self.latest_timestamp

LAYERS = 2 # I chose this arbitrarily based on documentation

def open_pcap_file(fname):
    try:
        return open(os.path.join(os.path.dirname(__file__), fname))
    except Exception:
        print('Invalid or missing pcap file')
        sys.exit(1)


def read_pcap_file(filename):
    # Open file and initialize variables
    testcap = open_pcap_file(filename)
    capfile = savefile.load_savefile(testcap, layers=LAYERS)

    if not capfile.valid:
        print('Invalid packet capture')
        sys.exit(1)
        
    print 'Opened', filename
    edges = [] # list of tuples of the form
    # (ip_source, ip_dest, timestamp, timestamp_us, num_bytes)
    nodes = ['Z'] # list of unique IP addresses
    # The 'Z' is a temporary placeholder - ugly but it's use to allow us
    # to do binary searches of the nodes array
    total_packets = len(capfile.packets)
    not_ipv4_packets = 0
    # We will not include non-ipv4 packet transfers (many are ARP) in our graph
    earliest_timestamp = None
    latest_timestamp = None

    # This will combine consecutive packets if they have the same source and
    # destinationa addresses. We will add beginning and final times to show
    # the time mrange. This can cut down on the number of edges, likely without
    # affecting our graph analysis
    prev_ip_source = None
    prev_ip_dest = None
    initial_timestamp = None
    initial_timestamp_us = None
    final_timestamp = None
    final_timestamp_us = None
    sum_num_bytes = 0
    for i in range(len(capfile.packets)):
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
        sum_num_bytes += num_bytes
        if ip_source == prev_ip_source and ip_dest == prev_ip_dest \
            and i != len(capfile.packets) - 1:
            final_timestamp = timestamp
            final_timestamp_us = timestamp_us
            continue
        elif prev_ip_source != None and prev_ip_dest != None:
            edges.append((prev_ip_source, prev_ip_dest, initial_timestamp, \
                initial_timestamp_us, final_timestamp, final_timestamp_us, \
                sum_num_bytes))
            
        prev_ip_source = ip_source
        prev_ip_dest = ip_dest
        initial_timestamp = timestamp
        initial_timestamp_us = timestamp_us
        final_timestamp = timestamp
        final_timestamp_us = timestamp_us
        sum_num_bytes = 0

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
    del nodes[-1]
    pcap_file = PcapFile(total_packets, not_ipv4_packets, edges, nodes, \
        earliest_timestamp, latest_timestamp)
    return pcap_file