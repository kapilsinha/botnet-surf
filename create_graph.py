'''
Intro to this package is on https://pypi.python.org/pypi/pypcapfile

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
from graph_tool.all import *
import bisect
'''
Bisect allows us to create a list of node IP addresses that is sorted as it
goes (allowing for log(n) search time - which is nice since we can quickly
check if that IP address is in list and can quickly find the indices of the
vertices - as the order of nodes in this list is the same order they are
added to the graph)
'''

class PcapGraph:
    '''
    All these variables should remain internal to this class (not to be accessed
    from the GUI). The GUI should only interact with the make_graph function
    - passing in an interval length and step length if it changes from when the
    class was initialized and receiving the graph g
    '''
    def __init__(self, filename, step_length = 150, interval_length = 300):
        testcap = self.open_pcap_file(filename)
        self.packet_generator \
            = savefile.load_savefile(testcap, layers=2, lazy=True).packets
        self.step_length = step_length
        self.interval_length = interval_length
        # Edges are a list of tuples of the form (ip_source, ip_dest, timestamp, num_bytes)
        self.edges = []
        self.nodes = []
        # I "use up" an edge from the graph to get this earliest_timestamp, but
        # it's pretty much negligible and I need the earliest timestamp to
        # increment it using the step_length
        # Note: the earliest_timestamp is set so that it gets incremented in the 
        # read_pcap_file below. The timestamp fields are invalid when the object
        # has just been constructed
        self.earliest_timestamp = self.packet_generator.next().timestamp \
            - self.step_length
        self.latest_timestamp = 0
        self.last_g = None # contains the most recent g variable

    def open_pcap_file(self, fname):
        try:
            return open(os.path.join(os.path.dirname(__file__), fname))
        except Exception:
            print('Invalid or missing pcap file')
            sys.exit(1)

    '''
    Iterates over the packet generator and updates edges, nodes,
    earliest_timestamp, and latest_timestamp appropriately 
    '''
    def read_pcap_file(self):
        # We will not include non-ipv4 packet transfers (many are ARP) in our graph
        try:
            self.earliest_timestamp += self.step_length
            self.nodes = ['Z']
            start_index = 0
            for i in range(len(self.edges)):
                if self.edges[i][2] >= self.earliest_timestamp:
                    start_index = i
                    break
            self.edges = self.edges[start_index:]
            # the above is more efficient though the below is cleaner
            # self.edges[:] = [e for e in self.edges if e[2] >= self.earliest_timestamp]
            for edge in self.edges:
                ip_source = edge[0]
                ip_dest = edge[1]
                i = bisect.bisect_left(self.nodes,ip_source)
                if self.nodes[i] != ip_source:
                    self.nodes.insert(i, ip_source)
                i = bisect.bisect_left(self.nodes, ip_dest)
                if self.nodes[i] != ip_dest:
                    self.nodes.insert(i, ip_dest)
            while True:
                p = self.packet_generator.next() 
                self.latest_timestamp = p.timestamp
                # I will ignore timestamp_us (shouldn't need so much precision)
                
                if p.timestamp > self.earliest_timestamp + self.interval_length:
                    # update the earliest_timestamp for when the function is called again
                    break

                if p.packet.type != 2048: # if EtherType is not IPv4
                    continue

                ip_source = p.packet.payload.src
                ip_dest = p.packet.payload.dst
                
                num_bytes = len(p.packet.payload.payload) // 2

                # I removed the portion that combines consecutive packets if 
                # they are from the same source and to the same destination
                self.edges.append((ip_source, ip_dest, p.timestamp, num_bytes))

                '''
                # Less efficient
                if ip_source not in self.nodes:
                    self.nodes.append(ip_source)
                if ip_dest not in nodes:
                    self.nodes.append(ip_dest)
                self.nodes.sort()
                '''
                # Generates a sorted array of IP addresses of the devices
                j = bisect.bisect_left(self.nodes, ip_source)
                if self.nodes[j] != ip_source:
                    self.nodes.insert(j, ip_source)
                j = bisect.bisect_left(self.nodes, ip_dest)
                if self.nodes[j] != ip_dest:
                    self.nodes.insert(j, ip_dest)

        except StopIteration: # exception thrown when our generator runs out
            pass
        del self.nodes[-1]

    def make_graph(self, save_graph=False, save_filename="graph_structure.gt"):
        self.read_pcap_file()
        # If our step would take our earliest timestamp past the end of the
        # generator (and latest_timestamp), we return the previous g
        if self.earliest_timestamp > self.latest_timestamp:
            return self.last_g
        g = Graph()
        # Create internal property maps
        g.graph_properties["earliest_timestamp"] = g.new_graph_property("long")
        g.graph_properties["earliest_timestamp"] = self.earliest_timestamp
        g.graph_properties["latest_timestamp"] = g.new_graph_property("long")
        g.graph_properties["latest_timestamp"] = self.latest_timestamp

        g.vertex_properties["ip_address"] = g.new_vertex_property("string")

        g.edge_properties["timestamp"] = g.new_edge_property("long")
        g.edge_properties["num_bytes"] = g.new_edge_property("int")
        g.edge_properties["ip_source"] = g.new_edge_property("string")
        g.edge_properties["ip_dest"] = g.new_edge_property("string")

        # sorted list of tuples of the form (ip_address, vertex_index)
        vertex_ip_list = []
        for node in self.nodes:
            v = g.add_vertex()
            g.vp.ip_address[v] = node
            bisect.insort_left(vertex_ip_list, (node, int(v)))

        for edge in self.edges:
            # connect vertices with the source and destination IP address
            # and add to its properties
            # Maybe could have used graph_tool.util.find_vertex(g, prop, match)
            v1 = bisect.bisect_left(vertex_ip_list, (edge[0], 0))
            v2 = bisect.bisect_left(vertex_ip_list, (edge[1], 0))
            e = g.add_edge(v1, v2)
            g.ep.ip_source[e] = edge[0]
            g.ep.ip_dest[e] = edge[1]
            g.ep.timestamp[e] = edge[2]
            g.ep.num_bytes[e] = edge[3]

        if save_graph == True:
            save_type = save_filename.split(".")[1]
            if save_type in ["gt", "graphml", "xml", "dot", "gml"]:
                g.save(save_filename, fmt = save_type)
            else:
                print("Invalid save type. Graph not saved.")
        self.last_g = g
        return g
"""
filename = sys.argv[1]
pcap_graph = PcapGraph(filename)
g1 = pcap_graph.make_graph()

print pcap_graph.step_length
print pcap_graph.interval_length
print len(pcap_graph.edges)
print len(pcap_graph.nodes)
print pcap_graph.earliest_timestamp
print pcap_graph.latest_timestamp

g2 = pcap_graph.make_graph()

print pcap_graph.step_length
print pcap_graph.interval_length
print len(pcap_graph.edges)
print len(pcap_graph.nodes)
print pcap_graph.earliest_timestamp
print pcap_graph.latest_timestamp
"""
