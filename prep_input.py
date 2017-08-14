import numpy as np
from random import random
from graph_tool.all import *
import create_graph
import scenario_info

'''
Normalizes a vertex characteristic by calculating (x - min)/(max - min)
'''
def normalize(array):
	# Note that some measures of centrality can be NaN so I change the NaN
	# values to 0
	array = 0.05 + 0.90 * (array - array.min()) / float(array.max() - array.min())
	array = np.nan_to_num(array)
	return array

'''
Creates balanced x and y files with the same name as the input but with an
added "_balanced". Returns just the name of the files created
Parameters:
x_file - file with unbalanced number of x inputs
y_file - file with unbalanced number of y inputs
ratio - desired ratio of non-malicious to malicious nodes
'''
def balance_data(x_file, y_file, ratio=5):
	x_out_filename = x_file.split('.')[0] + '_balanced.txt'
	y_out_filename = y_file.split('.')[0] + '_balanced.txt'
	x_in = open(x_file, 'r')
	x_out = open(x_out_filename, 'w')
	y_in = open(y_file, 'r')
	y_out = open(y_out_filename, 'w')

	line_count, positive_count = 0, 0
	with open(y_file, 'r') as f:
		for line in f:
			if float(line) != 0:
				positive_count += 1
			line_count += 1

	probability = float(ratio * positive_count)/line_count

	index_list = [] # list of line indices of lines that are added to outfile
	i = 0
	for line in y_in:
		if float(line) == 0:
			add_to_file = random() < probability
			if add_to_file:
				index_list.append(i)
				y_out.write(line)
		else:
			index_list.append(i)
			y_out.write(line)
		i += 1

	j, k = 0, 0
	for line in x_in:
		if k >= len(index_list):
			break
		if j == index_list[k]:
			x_out.write(line)
			k += 1
		j += 1

	x_in.close()
	x_out.close()
	y_in.close()
	y_out.close()
	return x_out_filename, y_out_filename

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
Separates the x and y numpy arrays into x_train, y_train, x_test, and y_test
Parameters:
x - x numpy array
y - y numpy array
training_proportion - Decimal equivalent of how much of the arrays are to be
                      used for the training sets
'''
def separate_into_sets(x, y, training_proportion=0.7):
	if training_proportion > 1 or training_proportion < 0:
		print "Training proportion must be 0 and 1"
		sys.exit(1)
	x_train = x[0:int(training_proportion * len(x))]
	y_train = y[0:int(training_proportion * len(y))]
	x_test = x[int(training_proportion * len(x)):]
	y_test = y[int(training_proportion * len(y)):]
	return x_train, y_train, x_test, y_test