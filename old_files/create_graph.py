import sys
from graph_tool.all import *
import bisect
import process_pcap_file

def make_graph(filename, save_graph=False, save_filename="graph_structure.gt"):
	pcap_file = process_pcap_file.read_pcap_file(filename)
	"""
	print pcap_file.get_total_packets()
	print pcap_file.get_not_ipv4_packets()
	#print pcap_file.get_edges()
	print len(pcap_file.get_edges())
	print pcap_file.get_nodes()
	print pcap_file.get_earliest_timestamp()
	print pcap_file.get_latest_timestamp()
	"""
	g = Graph()
	# Create internal property maps
	g.graph_properties["earliest_timestamp"] = g.new_graph_property("long")
	g.graph_properties["earliest_timestamp"] = pcap_file.get_earliest_timestamp()
	g.graph_properties["latest_timestamp"] = g.new_graph_property("long")
	g.graph_properties["latest_timestamp"] = pcap_file.get_latest_timestamp()

	g.vertex_properties["ip_address"] = g.new_vertex_property("string")

	g.edge_properties["initial_timestamp"] = g.new_edge_property("long")
	g.edge_properties["initial_timestamp_us"] = g.new_edge_property("long")
	g.edge_properties["final_timestamp"] = g.new_edge_property("long")
	g.edge_properties["final_timestamp_us"] = g.new_edge_property("long")
	g.edge_properties["num_bytes"] = g.new_edge_property("int")
	g.edge_properties["ip_source"] = g.new_edge_property("string")
	g.edge_properties["ip_dest"] = g.new_edge_property("string")

	# sorted list of tuples of the form (ip_address, vertex_index)
	vertex_ip_list = []
	for node in pcap_file.get_nodes():
		v = g.add_vertex()
		g.vp.ip_address[v] = node
		bisect.insort_left(vertex_ip_list, (node, int(v)))

	for edge in pcap_file.get_edges():
		# connect vertices with the source and destination IP address
		# and add to its properties
		# Maybe could have used graph_tool.util.find_vertex(g, prop, match)
		v1 = bisect.bisect_left(vertex_ip_list, (edge[0], 0))
		v2 = bisect.bisect_left(vertex_ip_list, (edge[1], 0))
		e = g.add_edge(v1, v2)
		g.ep.ip_source[e] = edge[0]
		g.ep.ip_dest[e] = edge[1]
		g.ep.initial_timestamp[e] = edge[2]
		g.ep.initial_timestamp_us[e] = edge[3]
		g.ep.final_timestamp[e] = edge[4]
		g.ep.final_timestamp_us[e] = edge[5]
		g.ep.num_bytes[e] = edge[6]

	if save_graph == True:
		save_type = save_filename.split(".")[1]
		if save_type in ["gt", "graphml", "xml", "dot", "gml"]:
			g.save(save_filename, fmt = save_type)
		else:
			print("Invalid save type. Graph not saved.")
	return g
"""
make_graph("datasets/normal-capture-20110817.pcap", save_graph=True, \
	save_filename = "graph_structure.dot")
make_graph("datasets/normal-capture-20110817.pcap", save_graph=True, \
	save_filename = "graph_structure.graphml")
make_graph("datasets/normal-capture-20110817.pcap", save_graph=True, \
	save_filename = "graph_structure.xml")
make_graph("datasets/normal-capture-20110817.pcap", save_graph=True, \
	save_filename = "graph_structure.gml")
make_graph("datasets/normal-capture-20110817.pcap", save_graph=True, \
	save_filename = "graph_structure.gt")
"""