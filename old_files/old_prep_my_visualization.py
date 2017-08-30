import sys, os
import tensorflow as tf
import numpy as np
from graph_tool.all import *
# import matplotlib.pyplot as plt
# from random import random
#import scipy.io

import prep_time_series_input
import scenario_info
import create_graph
from self_organizing_map import SOM

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
	height, length = 5, 5 # SOM dimensions
	# Train a 5x5 SOM with 500 iterations
	
	print "Training the SOM"
	som = SOM(length, height, VECTOR_SIZE, 100)
	som.train(x, verbose = True)
	 
	# Get output grid
	clusters = np.array(som.get_centroids())
	# clusters = np.reshape(clusters, (length * height, VECTOR_SIZE))
	mapped = som.map_vects(x)
	grid_map = som.get_grid_mapping(mapped)
	num_grid = [[len(grid_map[i][j]) for j in range(len(grid_map[i]))] \
	    for i in range(len(grid_map))]
	print num_grid
	# Sort clusters by distance (in their vectors) from the largest cluster
	max_cluster_row = 0
	max_cluster_col = 0
	max_cluster_vector = None
	max_cluster_size = 0
	for row in range(len(num_grid)):
		for col in range(len(num_grid[row])):
			if num_grid[row][col] > max_cluster_size:
				max_cluster_row = row
				max_cluster_col = col
				max_cluster_vector = clusters[row][col]
				max_cluster_size = num_grid[row][col]
	print max_cluster_row
	print max_cluster_col
	print max_cluster_vector
	print max_cluster_size
	cluster_distances = []
	for row in range(len(clusters)):
		for col in range(len(clusters[row])):
			cluster_distances.append(np.linalg.norm(max_cluster_vector - clusters[row][col]))
	clusters = np.reshape(clusters, (length * height, VECTOR_SIZE))
	print clusters
	print cluster_distances
	# [clusters for _,clusters in sorted(zip(cluster_distances,clusters))]
	clusters = [clusters for _,clusters in sorted(zip(cluster_distances,clusters))]
	for i in range(len(clusters)):
		clusters[i] = list(clusters[i])
	print clusters
	with open("scenario_11_som_" + str(height) + "_" + str(length) + \
		"_clusters.txt", "w") as f:
		f.write(str(clusters))
	'''
	# Output from above (to avoid running it again)
	with open("scenario_11_som_" + str(height) + "_" + str(length) + \
		"_clusters.txt", "r") as f:
		clusters = eval(f.readline())
	# print clusters
	'''
	# The below must be an LSTM input file
	filename_x = sys.argv[3]
	filename_y = sys.argv[4]
	# mat_filename = 'output_mat_file.mat'

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

	arr = np.ndarray(shape=(num_time_intervals + 1), dtype=object)
	nodes_array = np.array(range(len(y))) #[np.newaxis].transpose()
	arr[0] = nodes_array
	time_step = 1
	botnet_node_clusters = [] # list of the form [[clusters containing botnets] * time intervals]
	for x in x_total: # Iterate over time stamps
		i = 0
		print "Time interval " + str(time_step) + ' / ' \
			+ str(num_time_intervals)
		cluster_array = np.array([])
		current_botnet_clusters = []
		for sample in x:
			cluster_number = most_similar_group(sample, clusters)
			cluster_array = np.append(cluster_array, cluster_number)
			if y[i] != 0:
				print "Botnet node: cluster " + str(cluster_number + 1)
				current_botnet_clusters.append(cluster_number + 1)
			i += 1
		botnet_node_clusters.append(list(set(current_botnet_clusters)))
		print "Unique clusters: ", str(np.unique(cluster_array + 1))
		arr[time_step] = cluster_array
		time_step += 1

	# contains lists of tuples where each list represents time step A to B
	# and tuples are in the form (prev_cluster, next_cluster, number of this transition)
	transitions_arr = []
	for i in range(1, num_time_intervals):
		all_time_interval_transitions = []
		for j in arr[0]:
			all_time_interval_transitions.append((int(arr[i][j] + 1), int(arr[i + 1][j] + 1)))
		time_interval_transitions = list(set(all_time_interval_transitions)) # unique cluster transitions
		for i in range(len(time_interval_transitions)):
			time_interval_transitions[i] = (time_interval_transitions[i][0], \
				time_interval_transitions[i][1], \
				all_time_interval_transitions.count(time_interval_transitions[i]))
		time_interval_transitions.sort()
		transitions_arr.append(time_interval_transitions)

	with open("botnet_clusters_" + str(height) + "_" + str(length) \
		+ ".txt", "w") as output:
		output.write(str(botnet_node_clusters))

	with open("cluster_transitions_" + str(height) + "_" + str(length) \
		+ ".txt", "w") as output:
	    output.write(str(transitions_arr))

main()
