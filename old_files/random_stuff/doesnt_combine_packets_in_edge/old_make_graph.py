import sys
import old_process_pcap_file
from graph_tool.all import *
import bisect

try:
	FILENAME = sys.argv[1]
except:
	print("The command-line argument should be the name of the pcap file")
	sys.exit(1)

pcap_file = process_pcap_file.read_pcap_file(FILENAME)

g = Graph()
# Create internal property maps
g.graph_properties["num_nodes"] = g.new_graph_property("int")
g.graph_properties["num_nodes"] = len(pcap_file.get_nodes())
g.graph_properties["earliest_timestamp"] = g.new_graph_property("long")
g.graph_properties["earliest_timestamp"] = pcap_file.get_earliest_timestamp()
g.graph_properties["latest_timestamp"] = g.new_graph_property("long")
g.graph_properties["latest_timestamp"] = pcap_file.get_latest_timestamp()

g.vertex_properties["ip_address"] = g.new_vertex_property("string")

g.edge_properties["timestamp"] = g.new_edge_property("long")
g.edge_properties["timestamp_us"] = g.new_edge_property("long")
g.edge_properties["num_bytes"] = g.new_edge_property("int")
g.edge_properties["ip_source"] = g.new_edge_property("string") # maybe unnecessary
g.edge_properties["ip_dest"] = g.new_edge_property("string") # maybe unnecessary

# sorted list of tuples of the form (ip_address, vertex_index)
vertex_ip_list = []
for node in pcap_file.get_nodes():
	v = g.add_vertex()
	g.vp.ip_address[v] = node
	bisect.insort_left(vertex_ip_list, (node, int(v)))


for edge in pcap_file.get_edges():
	# connect vertices with the source and destination IP address
	# and add to its properties
	v1 = bisect.bisect_left(vertex_ip_list, (edge[0], 0))
	v2 = bisect.bisect_left(vertex_ip_list, (edge[1], 0))
	e = g.add_edge(v1, v2)
	g.ep.ip_source[e] = edge[0]
	g.ep.ip_dest[e] = edge[1]
	g.ep.timestamp[e] = edge[2]
	g.ep.timestamp_us[e] = edge[3]
	g.ep.num_bytes[e] = edge[4]

graph_draw(g, eorder=g.ep.timestamp, edge_pen_width = 1.2, \
	vertex_size = 10, pos=sfdp_layout(g), \
	output_size=(1000, 1000), output="graph.pdf")

print pcap_file.get_total_packets()
print pcap_file.get_not_ipv4_packets()
#print pcap_file.get_edges()
print len(pcap_file.get_edges())
print pcap_file.get_nodes()
print pcap_file.get_earliest_timestamp()
print pcap_file.get_latest_timestamp()
