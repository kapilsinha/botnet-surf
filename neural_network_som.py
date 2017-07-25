import sys, os
import tensorflow as tf
import numpy as np
from graph_tool.all import *
import matplotlib.pyplot as plt
from random import random
import create_graph
from self_organizing_map import SOM

"""
Vertex features - all 12 of these are calculated using graph-tool's functions:
["Out-degree", "In-degree", "# of in-neighbors", "# of out-neighbors", 
 "Page Rank", "Betweenness", "Closeness", "Eigenvector", "Katz",
 "Authority centrality", "Hub centrality", "Clustering coefficient"]
The above features will be normalized and placed in a vector for each vertex
in each time interval
"""

VECTOR_SIZE = 12 # number of vertex characteristics in the vector

# Disable print statements
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Enable print stements
def enablePrint():
    sys.stdout = sys.__stdout__

'''
Normalizes a vertex characteristic by calculating (x - min)/(max - min)
'''
def normalize(array):
	# Note that some measures of centrality can be NaN so I change the NaN
	# values to 0
	array = .05 + .90 * (array - array.min()) / float(array.max() - array.min())
	array = np.nan_to_num(array)
	return array

'''
Generates the input numpy arrays (size VECTOR_SIZE) for the model by reading
in the pcap file. Note that this can be very time consuming for big pcap files
Parameters:
pcap_filename - Name of pcap file
do_save - True if input arrays are saved in a file
savefile_x - Name of x file
savefile_y Name of y file

NOTE: I REALIZED THIS AFTER THE FACT BUT I SHOULD HAVE KEPT EACH GRAPH AS A 
BATCH AND NOT NORMALIZE IT WHEN READING IN THE FILE AND INSTEAD APPLYING THE
KERAS FUNCTION normalize_batch_in_training ON THE BATCH.
Changing this now will require re-reading the input files (which will take a 
long time), so try experimenting with this later.
'''
def generate_input_arrays(pcap_filename, botnet_nodes, pcap_duration, \
	step_length = 60, interval_length = 120, do_save=True, \
	savefile_x='x.txt', savefile_y='y.txt', verbose = True):
	pcap_graph = create_graph.PcapGraph(pcap_filename, \
		step_length = step_length, interval_length = interval_length)
	# I split the input or output values into training and testing set later
	# Input: 2D array of size (num_vertices, VECTOR_SIZE)
	x = np.array([]).reshape(0, VECTOR_SIZE)
	# Output: array of length num_vertices
	# (1 if the corresponding vertex is malicious, 0 if it is non-malicious)
	y = np.array([])

	num = 1

	if verbose == False:
		blockPrint()

	#for i in range(int(float(pcap_duration - interval_length)/step_length)):
	i = -1
	while pcap_graph.reached_file_end == False:
		i += 1
		'''
		IF the program freezes, calculate the last i based on the percentage
		printed and write the number after the < sign
		'''
		print str(float(100 * i)/int(float(pcap_duration - interval_length) \
			/step_length)) + "%"
		'''
		if i < 12:
			print "Dummy graph..."
			pcap_graph.dummy_make_graph()
			continue
		'''
		g = pcap_graph.make_graph()
		# Degree
		print "Out-degrees..."
		outd = normalize(g.get_out_degrees(g.get_vertices()))
		print "In-degrees..."
		ind = normalize(g.get_in_degrees(g.get_vertices()))
		# Number of neighbors
		print "In-neighbors..."
		inn = np.array([])
		print "Out-neighbors..."
		outn = np.array([])
		for v in g.get_vertices():
			inn = np.append(inn, len(g.get_in_neighbours(v)))
			outn = np.append(outn, len(g.get_out_neighbours(v)))
		inn = normalize(inn)
		outn = normalize(outn)
		# Centrality
		print "Pagerank..."
		pr = normalize(pagerank(g).a)
		print "Betweenness..."
		b = normalize(betweenness(g)[0].a)
		print "Closeness..."
		c = normalize(closeness(g).a)
		print "Eigenvector..."
		# this eigenvector algorithm often has a very slow convergence so I've 
		# added a max_iter which makes it not get stuck here...maybe remove
		# this metric since it doesn't seem useful
		ev = normalize(eigenvector(g, max_iter = 500)[1].a)
		print "Katz..."
		k = normalize(katz(g).a)
		print "Authority..."
		auth = normalize(hits(g)[1].a)
		print "Hub..."
		# Clustering
		hub = normalize(hits(g)[2].a)
		print "Clustering..."
		clustering = normalize(local_clustering(g).a)
		# this seems to take a long time to run
		print "Appending to x..."
		x = np.append(x, np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
			auth, hub, clustering]).transpose(), axis=0)
		
		print "Appending to y..."
		for v in g.get_vertices():
			# x = np.append(x, [[outd[v], ind[v], inn[v], outn[v], pr[v], \
			# b[v], c[v], ev[v], k[v], auth[v], hub[v], clustering[v]]], \
			# axis=0)
			
			# If the node is a Botnet node and has been infected (the graph's
			# latest timestamp is greater than the node's infection time),
			# output is 1. Else output is 0
			if g.vp.ip_address[v] in botnet_nodes.keys() and \
				g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]]:
					y = np.append(y, 1)
			else:
				y = np.append(y, 0)
		# Save the file every 1% in case the loop fails at some point
		if do_save and float(100 * i)/int(float(pcap_duration \
			- interval_length)/step_length) >= num:
			num += 1
			np.savetxt(savefile_x, x)
			np.savetxt(savefile_y, y)
	enablePrint()
	print "# of inputs: " + str(len(x))
	print "# of outputs: " + str(len(y))
	print "Finished creating the input file."
	return x, y

'''
Loads the input numpy arrays from file
Parameters:
filename_x - Name of x file
filename_y Name of y file
'''
def load_input_arrays(filename_x='x.txt', filename_y='y.txt'):
	x = np.loadtxt(filename_x)
	y = np.loadtxt(filename_y)
	print "Loaded the input arrays"
	return x, y

'''
Returns the pcap duration (in seconds) given the scenario number
Note that this is given in more detail in infected_hosts.txt
'''
def get_pcap_duration(scenario):
	if scenario == 9:
		return 18500
	if scenario == 10:
		return 17000
	if scenario == 11:
		return 936
	if scenario == 12:
		return 4400

'''
Returns the botnet_nodes dictionary given the scenario number.
Note that this is given in more detail in infected_hosts.txt
'''
def get_botnet_nodes(scenario):
	if scenario == 9:
		return {"147.32.84.165": 1313583848, "147.32.84.191": 1313585000, \
				"147.32.84.192": 1313585300, "147.32.84.193": 1313585685, \
		        "147.32.84.204": 1313585767, "147.32.84.205": 1313585878, \
		        "147.32.84.206": 1313586042, "147.32.84.207": 1313586116, \
		        "147.32.84.208": 1313586193, "147.32.84.209": 1313586294}
	if scenario == 10:
		return {"147.32.84.165": 1313658370, "147.32.84.191": 1313658392, \
                "147.32.84.192": 1313658341, "147.32.84.193": 1313658412, \
                "147.32.84.204": 1313658313, "147.32.84.205": 1313658435, \
                "147.32.84.206": 1313658286, "147.32.84.207": 1313658260, \
                "147.32.84.208": 1313658232, "147.32.84.209": 1313658185}
	if scenario == 11:
		return {"147.32.84.165": 1313675308, "147.32.84.191": 1313675308, \
                "147.32.84.192": 1313675308}
	if scenario == 12:
		return {"147.32.84.165": 1313743359, "147.32.84.191": 1313743638, \
                "147.32.84.192": 1313743825}

'''
Returns the number of botnet nodes in a 1-D list of indices corresponding to
the indices of the input array
Parameters:
lst - list of indices corresponding to those in the input arrays
y - NumPy array for the y input array (a nonzero value indicates a botnet node)
'''
def count_botnet_nodes(lst, y):
	num_botnet_nodes = 0
	for i in lst:
		if y[i] != 0:
			num_botnet_nodes += 1
	return num_botnet_nodes

def main():
	step_length = 60
	interval_length = 120

	data_scenario = 11
	#pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = get_botnet_nodes(data_scenario)
	pcap_duration = get_pcap_duration(data_scenario) # * 0.1

	'''
	savefile_x = 'Scenario_' + str(data_scenario) + '_model/' + \
		'x_scenario_' + str(data_scenario) + '.txt'
	savefile_y = 'Scenario_' + str(data_scenario) + '_model/' + \
		'y_scenario_' + str(data_scenario) + '.txt'
	'''
	savefile_x = 'x_scenario_' + str(data_scenario) + '_one_graph.txt'
	savefile_y = 'y_scenario_' + str(data_scenario) + '_one_graph.txt'
	
	'''
	x, y = generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=True, savefile_x=savefile_x, savefile_y=savefile_y, verbose = True)
	'''
	x, y = load_input_arrays(filename_x=savefile_x, filename_y=savefile_y)

	# Train a 5x5 SOM with 100 iterations
	som = SOM(5, 5, 12, 100)
	som.train(x, verbose = True)
	 
	# Get output grid
	image_grid = som.get_centroids()
	print image_grid
	 
	# Map colours to their closest neurons
	mapped = som.map_vects(x)
	# m x n matrix with each cell containing lists of indices of input vectors
	# mapped to it
	grid_map = som.get_grid_mapping(mapped)
	# m x n matrix with each cell containing the number of input vectors 
	# mapped to it
	num_grid = [[len(grid_map[i][j]) for j in range(len(grid_map[i]))] \
	    for i in range(len(grid_map))]
	num_botnet_grid = [[count_botnet_nodes(grid_map[i][j], y) for j in range(len(grid_map[i]))] \
	    for i in range(len(grid_map))]
	print num_grid
	print num_botnet_grid
	 
	# Plot
	#plt.imshow(image_grid)
	#plt.title('Color SOM')
	#plt.show()

main()
