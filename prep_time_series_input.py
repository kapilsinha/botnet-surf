import numpy as np
from random import random
from graph_tool.all import *
import create_graph

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
Creates undersampled x and y files with the same name as the input but with an
added "_balanced". Returns just the name of the files created
Parameters:
x - x NumPy array
y - y NumPy array
x_file - file with unbalanced number of x inputs
y_file - file with unbalanced number of y inputs
ratio - desired ratio of non-malicious to malicious nodes
'''
def balance_data(x, y, ratio=5):
	new_x = np.array([])
	new_y = np.array([])
	_, num_time_steps, feature_size = x.shape
	line_count, positive_count = 0, 0
	for element in y:
		if element != 0:
			positive_count += 1

	probability = float(ratio * positive_count)/len(y)

	index_list = [] # list of array indices that are added to out array
	i = 0
	for element in y:
		if element == 0:
			add_to_out_array = random() < probability
			if add_to_out_array:
				index_list.append(i)
				new_y = np.append(new_y, element)
		else:
			index_list.append(i)
			new_y = np.append(new_y, element)
		i += 1

	j, k = 0, 0
	while k < len(index_list):
		if j == index_list[k]:
			new_x = np.append(new_x, x[j])
			k += 1
		j += 1

	new_x = new_x.reshape(len(index_list), num_time_steps, feature_size)
	return new_x, new_y

'''
Creates x and y files broken into time windows with the same name as the input
but with an added "_windows". Returns just the name of the files created
Note that this is memory inefficient since it creates another giant array and
changes elements in it - ideally I could modify the text file directly - maybe
that would decrease RAM usage. This took so long for me to write for some
reason I'll stick with this for now...
Parameters:
x - x NumPy array
y - y NumPy array
window_num_steps - number of time steps per time window
window_step_size - number of time steps to step over between time windows
'''
def time_window_data(x, y, window_num_steps, window_step_size):
	if window_num_steps > len(x[0]):
		print "Time chunk is greater than the original number of time steps" \
			+ " Using original number of time steps as time chunk"
		window_num_steps = len(x[0])
	# Number of windows per sample
	num_windows = float(len(x[0]) - window_num_steps) / window_step_size + 1
	if num_windows != int(num_windows):
		num_windows = int(num_windows) + 1 # round up to nearest number
	else:
		num_windows = int(num_windows)

	new_x = np.empty([len(x) * num_windows, window_num_steps, len(x[0][0])])
	new_y = np.empty([len(y) * num_windows])
	
	j, k, l = 0, 0, window_num_steps
	for i in range(len(new_x)):
		new_x[i] = x[j][k:l]
		new_y[i] = y[j]
		if l == len(x[j]):
			k, l = 0, window_num_steps
			j += 1
		elif l + window_step_size > len(x[j]):
			k, l = len(x[j]) - window_num_steps, len(x[j])
		else:
			k += window_step_size
			l += window_step_size
	return new_x, new_y, len(x), num_windows

'''
Generates the input NumPy arrays (size VECTOR_SIZE) for the model by reading
in the pcap file. Note that this can be very time consuming for big pcap files
Parameters:
pcap_filename - Name of pcap file
do_save - True if input arrays are saved in a file
savefile_x - Name of x file
savefile_y Name of y file
'''
def generate_input_arrays(pcap_filename, botnet_nodes, pcap_duration, \
	step_length = 60, interval_length = 120, do_save=True, \
	savefile_x='x.txt', savefile_y='y.txt', verbose = True):
	pcap_graph = create_graph.PcapGraph(pcap_filename, \
		step_length = step_length, interval_length = interval_length)
	# Input: 3D array of size (num_vertices, VECTOR_SIZE, num_steps)
	x = np.array([])
	# Output: 1D array of length num_vertices (1 if malicious, 0 if not)
	y = np.array([])
	# Dictionary with IP addresses as keys and list of 12-vectors as the value
	dict_x = {}
	# Dictionary with IP addresses as keys and 1 or 0 as the value
	dict_y = {}

	num = 1

	if verbose == False:
		blockPrint()

	i = -1
	#for j in range(int(float(pcap_duration - interval_length)/step_length)):
	while pcap_graph.reached_file_end == False:
		i += 1
		print str(float(100 * i)/int(float(pcap_duration - interval_length) \
			/step_length)) + "%"

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
		print "Adding to dict_x..."
		temp = np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
			auth, hub, clustering]).transpose()
		
		# Add vertex vectors to dict_x
		# Consider changing the dictionaries to sorted lists so you can
		# do a binary search
		for v in g.get_vertices():
			# Pre-existing nodes that are present in this graph
			if g.vp.ip_address[v] in dict_x.keys():
				dict_x[g.vp.ip_address[v]].append(temp[v])
			# New nodes that first appear in this graph
			else:
				# pad the portion of the time-series that the node was absent
				# with zeros
				dict_x[g.vp.ip_address[v]] = [[0] * VECTOR_SIZE] * i
				dict_x[g.vp.ip_address[v]].append(temp[v])
		# Pre-existing nodes that are not present in this graph
		for key in dict_x.keys():
			# pad the portion of the time-series that the node is absent
			# with zeros
			if len(dict_x[key]) != i + 1:
				dict_x[key].append([0] * VECTOR_SIZE)
		# Save the file every 1% in case the loop fails at some point
		if do_save and float(100 * i)/int(float(pcap_duration \
			- interval_length)/step_length) >= num:
			num += 1
			with open(str('dict_') + savefile_x, 'w') as f:
				f.write(str(dict_x))
				print "Saved dict_x"
		"""
		"""

	print "Adding to dict_y..."
	for key in dict_x.keys():
		dict_y[key] = int(key in botnet_nodes.keys())
			#and g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]])
	if do_save:
		with open(str('dict_') + savefile_y, 'w') as f:
			f.write(str(dict_y))
			print "Saved dict_y"
	"""
	"""

	for key in dict_x.keys():
		# Append flat arrays for the vertices' time-series to create a 1D array
		x = np.append(x, [item for sublist in dict_x[key] for item in sublist])
		y = np.append(y, dict_y[key])
	# reshape(num_samples = # vertices, time_steps = # graphs, num_features)
	# https://stackoverflow.com/questions/38714959/understanding-keras-lstms
	# [[[num_features] * time_steps] * num_samples]
	x = x.reshape(len(dict_x.keys()), i + 1, VECTOR_SIZE)
	if do_save:
		with file(savefile_x, 'w') as outfile:
		    outfile.write('#{0}\n'.format(x.shape))
		    for x_slice in x:
		        np.savetxt(outfile, x_slice)
		np.savetxt(savefile_y, y)

	enablePrint()
	print "# of unique vertices / IP addresses: " + str(len(x))
	print "# of time steps / graphs: " + str(len(x[0]))
	print "# of features: " + str(len(x[0][0]))
	print "# of outputs: " + str(len(y))
	print "Finished creating the input file."
	return x, y

'''
Loads the input NumPy arrays from file
Parameters:
filename_x - Name of x file
filename_y Name of y file
'''
def load_input_arrays(filename_x='x.txt', filename_y='y.txt', x_shape = None):
	x = np.loadtxt(filename_x)
	y = np.loadtxt(filename_y)
	with open(filename_x, 'r') as f:
		array_shape = f.readline()[1:] # (x,y,z)
		# Uses the array shape written on the first line to reshape
		if x_shape != None:
			x = x.reshape(x.shape)
		else:
			x = x.reshape(eval(array_shape))
		# print "x.shape: ", str(x.shape)
	# print "y.shape: ", str(y.shape)
	print "Loaded the input arrays"
	return x, y

'''
Separates the x and y NumPy arrays into x_train, y_train, x_test, and y_test
Parameters:
x - x NumPy array
y - y NumPy array
training_proportion - Decimal equivalent of how much of the arrays are to be
                      used for the training sets
positive proportion - Decimal equivalent of how many positive instances are to
                      be used for the training sets (note that if the positive
                      proportion is specified, the training proportion is
                      ignored)
'''
def separate_into_sets(x, y, training_proportion=0.7, positive_proportion=None):
	if positive_proportion != None:
		if positive_proportion > 1 or positive_proportion < 0:
			print "Positive proportion must be 0 and 1. Using 0.7 as default"
			positive_proportion = 0.7
		positive_count = 0
		for element in y:
			if element == 1:
				positive_count += 1
		included_positives = int(float(positive_proportion) * positive_count)
		print str(included_positives), \
			" positive samples will be included in the training sets"
		print str(positive_count - included_positives), \
			" positive samples will be included in the testing sets"
		last_i = 0
		for i in range(len(y)):
			if y[i] == 1:
				included_positives -= 1
			if included_positives == 0:
				last_i = i
				break
		x_train = x[0:last_i + 1]
		y_train = y[0:last_i + 1]
		x_test = x[last_i + 1:]
		y_test = y[last_i + 1:]

	else:
		if training_proportion > 1 or training_proportion < 0:
			print "Training proportion must be 0 and 1. Using 0.7 as default"
			training_proportion = 0.7
		x_train = x[0:int(training_proportion * len(x))]
		y_train = y[0:int(training_proportion * len(y))]
		x_test = x[int(training_proportion * len(x)):]
		y_test = y[int(training_proportion * len(y)):]
	return x_train, y_train, x_test, y_test