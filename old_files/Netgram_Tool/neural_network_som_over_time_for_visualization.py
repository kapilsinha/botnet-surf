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

VECTOR_SIZE = 10 # number of vertex characteristics in the vector

# Disable print statements
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Enable print stements
def enablePrint():
    sys.stdout = sys.__stdout__

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
Takes in a vector and another group of vectors, returning the index of the
vector in the group of vectors that is closest to the input vector, based on
Euclidean disance
'''
def most_similar_group(vector, clusters):
	if np.array_equal(np.array([0] * len(vector)), vector):
		return 0 # 0 vector corresponds to index 0
	most_similar_group = 1 # index of most similar group
	min_dist = np.linalg.norm(clusters[0] - vector)
	for i in range(1, len(clusters)):
		dist = np.linalg.norm(clusters[i] - vector)
		if dist < min_dist:
			min_dist = dist
			most_similar_group = i + 1
	return most_similar_group
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
	# The below must be a regular SOM input file
	x, y = load_input_arrays(filename_x=sys.argv[1], filename_y=sys.argv[2])
	length, height = 5, 5 # SOM dimensions
	# Train a 5x5 SOM with 500 iterations
	
	print "Training the SOM"
	som = SOM(length, height, VECTOR_SIZE, 100)
	som.train(x, verbose = True)
	 
	# Get output grid
	clusters = np.array(som.get_centroids())
	clusters = np.reshape(clusters, (length * height, VECTOR_SIZE))
	
	print clusters

	# The below must be an LSTM input file
	filename_x = sys.argv[3]
	filename_y = sys.argv[4]
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
	arr = np.ndarray(shape=(num_time_intervals, 3), dtype=object)
	# nodes_array = np.array(range(len(y)))
	# the above gives a var x 1 matrix when I need a 1 x var matrix (below)
	# NOTE: I'M ADDING DUMMY NODES TO MAKE THE FIRST TIME STEP HAVE ALL THE GROUPS
	# (NEEEDED FOR THE VISUALIZATION TO SHOW THESE GROUPS)
	nodes_array = np.array(range(len(y) + (length * height + 1)))[np.newaxis].transpose()
	# nodes_array = np.array(range(len(y)))[np.newaxis].transpose()
	nodes_array += 1 # MATLAB INDICES START AT 1
	nodes_array = np.ndarray.astype(nodes_array, dtype=np.uint64)
	time_step = 0
	for x in x_total: # Iterate over time stamps
		i = 0
		print "Time interval " + str(time_step + 1) + ' / ' \
			+ str(num_time_intervals)
		cluster_array = np.array([])
		for sample in x:
			cluster_number = most_similar_group(sample, clusters)
			cluster_array = np.append(cluster_array, cluster_number)
			if y[i] != 0:
				print "Botnet node: cluster " + str(cluster_number + 1)
			i += 1

		'''
		if time_step == 0: # account for the dummy nodes
			cluster_array = np.append(cluster_array, range(length * height + 1))
		else:
			cluster_array = np.append(cluster_array, [0] * (length * height + 1))
		'''
		print "Actual (not dummy) clusters: ", str(np.unique(cluster_array + 1))
		cluster_array = np.append(cluster_array, range(length * height + 1))

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
		'''
		# Now I obviously can't use grid_map but I should eventually implement its 
		# equivalent so that I can identify the botnet nodes in the visualization
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
		'''
		# if time_step == 10:
		# 	break

	output_dict = {'data': arr}
	# print arr
	# print output_dict
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
