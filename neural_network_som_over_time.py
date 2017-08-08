import sys, os
import tensorflow as tf
import numpy as np
from graph_tool.all import *
import matplotlib.pyplot as plt
from random import random
import scipy.io

import prep_time_series_input
import scenario_info
import create_graph
from self_organizing_map import SOM
try:
	import NetgramCommunityEvolutionVisualization
except:
	print "Failed to import Netgram Python package. Exiting..."
	sys.exit(1)
"""
NOTE: Unlike the regular som.py file, this takes the same input as the LSTM
(because I need to generate an SOM for each time interval)
"""

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

'''
This function/program just saves the .mat file and does not run the
visualization tool
'''
def main():
	step_length = 60
	interval_length = 120
	
	data_scenario = 11
	#pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = scenario_info.get_botnet_nodes(data_scenario)
	pcap_duration = scenario_info.get_pcap_duration(data_scenario) # * 0.1

	'''
	savefile_x = 'x_scenario_' + str(data_scenario) + '_one_graph.txt'
	savefile_y = 'y_scenario_' + str(data_scenario) + '_one_graph.txt'
	
	x, y = prep_time_series_input.generate_input_arrays(pcap_file, \
		botnet_nodes, pcap_duration, step_length = step_length, \
		interval_length = interval_length, do_save=True, \
		savefile_x=savefile_x, savefile_y=savefile_y, verbose = True)
	
	x_total, y_total = prep_time_series_input. \
		load_input_arrays(filename_x=savefile_x, filename_y=savefile_y)
	'''
	filename_x = sys.argv[1]
	filename_y = sys.argv[2]
	mat_filename = 'output_mat_file.mat'

	x_total, y = prep_time_series_input.load_input_arrays(filename_x \
		= filename_x, filename_y = filename_y)
	num_samples = len(x_total)

	"""
	The x and y are now in the shape [[[feature size] * time_stamps] * samples]
	but we need it in the shape [[[feature size] * samples] * time_stamps] to
	represent all samples over time intervals - hence we transpose the matrix.
	The y is in the proper shape and can be re-used for every time interval in
	x_total
	"""
	x_total = np.transpose(x_total, axes=[1,0,2])
	num_time_intervals = len(x_total)

	# Dictionary to follow the layout of a .mat file
	arr = np.ndarray(shape=(3, 3), dtype=object)
	# nodes_array = np.array(range(len(y)))
	# the above gives a var x 1 matrix when I need a 1 x var matrix (below)
	nodes_array = np.array(range(len(y)))[np.newaxis].transpose()
	nodes_array += 1 # MATLAB INDICES START AT 1
	nodes_array = np.ndarray.astype(nodes_array, dtype=np.uint64)
	time_step = 0
	length, height = 5, 5 # SOM dimensions
	# To keep the visualization clean, I will sort the groups by size:
	# the lowest indexed cluster contains the largest cluster, etc.
	# so that the smallest index contains the smallest cluster
	for x in x_total: # Iterate over time stamps
		alive_nodes = np.array([]) # contains indices of nodes present in graph (non-zero arrays)
		alive_x = np.array([]) # contains alive nodes in x
		vector_size = len(x[0])
		zero_array = np.array([0] * vector_size)
		for i in range(len(x)):
			if not np.array_equal(x[i], zero_array):
				alive_nodes = np.append(alive_nodes, i)
				alive_x = np.append(alive_x, x[i])
		# This array is not flattened so we reshape it to (number of samples, vector size)
		alive_x = np.reshape(alive_x, (len(alive_x)/vector_size, vector_size))
		# Train a 5x5 SOM with 1 iteration
		print "Time interval " + str(time_step + 1) + ' / ' \
			+ str(num_time_intervals)
		som = SOM(length, height, VECTOR_SIZE, 1)
		som.train(alive_x, verbose = True)
		 
		# Get output grid
		#image_grid = som.get_centroids()
		#print image_grid
		 
		# Map vectors to their closest neurons
		mapped = som.map_vects(x)
		#print 'mapped: ', str(mapped)

		cluster_array = np.array([])
		j = 0
		k = 0
		for i in range(len(x)):
			if i == alive_nodes[j]:
				cluster_array = np.append(cluster_array, mapped[k][0] * length \
					+ mapped[k][1] + 1)
				j = min(j + 1, len(alive_nodes) - 1)
				k += 1
			else:
				# The lowest indexed cluster consists of dead nodes
				cluster_array = np.append(cluster_array, 0)

		
		# Sort the clusters in descending order of size (number of nodes)
		count_dict = {}
		sorted_count_dict = {}
		for i in range(length * height + 1): # number of clusters
			count_dict[i] = 0
		for element in cluster_array:
			count_dict[element] += 1
		values = count_dict.values()
		values_copy = count_dict.values()
		keys = count_dict.keys()
		# Sorted_keys contains keys sorted by size of values
		sorted_keys = [keys for (values,keys) in sorted(zip(values,keys))]
		values_copy.sort()
		values_copy = values_copy[::-1]
		for i in range(length * height + 1): # number of clusters
			sorted_count_dict[sorted_keys[i]] = values_copy[i]
		for element in cluster_array:
			element = sorted_count_dict[element]
		

		cluster_array = cluster_array[np.newaxis].transpose()
		cluster_array += 1 # MATLAB INDICES START AT 1
		cluster_array = np.ndarray.astype(cluster_array, dtype=np.uint64)

		arr[time_step][0] = np.array([0])
		# ^ dummy variable - eventually I can remove this and modify the MATLAB code
		arr[time_step][1] = nodes_array
		arr[time_step][2] = cluster_array
		time_step += 1
		# m x n matrix with each cell containing lists of indices of input vectors
		# mapped to it
		grid_map = som.get_grid_mapping(mapped)
		# print 'grid_map: ', str(grid_map)
		# m x n matrix with each cell containing the number of input vectors 
		# mapped to it
		num_grid = [[len(grid_map[i][j]) for j in range(len(grid_map[i]))] \
		    for i in range(len(grid_map))]
		num_botnet_grid = [[count_botnet_nodes(grid_map[i][j], y) for j in \
			range(len(grid_map[i]))] for i in range(len(grid_map))]
		print num_grid
		print num_botnet_grid
		if time_step == 3:
			break

	output_dict = {'data': arr}
	print arr
	print output_dict
	print "Saving mat file"
	scipy.io.savemat(mat_filename, output_dict)
	# For some reason the mat file is created and saved just fine but the below
	# portion crashes...for now I will just use this generated .mat file and
	# make do, but eventually this needs to be fixed
	'''
	print "Running MATLAB visualization"
	a = NetgramCommunityEvolutionVisualization.initialize()
	a.run_script(mat_filename)
	# Prevent the program from exiting as soon as the figure is created
	raw_input("\nClick enter to exit the program...")
	sys.exit(0)
	'''

main()
