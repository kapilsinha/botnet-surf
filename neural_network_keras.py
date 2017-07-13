import sys, os
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.models import load_model
import numpy as np
import create_graph
from graph_tool.all import *

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
	array = (array - array.min()) / float(array.max() - array.min())
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

	for i in range(int(float(pcap_duration - interval_length)/step_length)):
	#i = -1
	#while pcap_graph.reached_file_end == False:
	#	i += 1
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
		if pcap_graph.reached_file_end == True:
			print "Reached the end of the pcap file in the training phase"
			sys.exit(1)

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
			if g.vp.ip_address[v] in botnet_nodes.keys(): #and \
				#g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]]:
				# REMOVE THE TIMESTAMP IF NOT TESTING ON SCENARIO 10
					y = np.append(y, 1)
			else:
				y = np.append(y, 0)
		# Save the file every 1% in case the loop fails at some point
		if do_save and float(100 * i)/int(float(pcap_duration \
			- interval_length)/step_length) > num:
			num += 5
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
	if training_proportion >= 1 or training_proportion <= 0:
		print "Training proportion must be 0 and 1"
		sys.exit(1)
	x_train = x[0:int(training_proportion * len(x))]
	y_train = y[0:int(training_proportion * len(y))]
	x_test = x[int(training_proportion * len(x)):]
	y_test = y[int(training_proportion * len(y)):]
	return x_train, y_train, x_test, y_test

'''
Trains the model
Parameters:
x_train - numpy array for x training set
y_train - numpy array for y training set
pcap_duration - pcap duration (seconds) - available on CTU website
step_length - step duration (seconds)
save_model - True if model is saved in an h5 file
savefile - name of file that the model is saved to
'''
def create_model(x_train, y_train, pcap_duration, step_length, \
	save_model=True, savefile="model.h5"):
	print "Starting the creation of the model"
	model = Sequential()
	# Input arrays of shape (num_vertices, 12) and
	# output arrays of shape (num_vertices, 1)
	model.add(Dense(15, input_dim=12, activation='relu'))
	# Dropout: Randomly set half (arbitrarily fraction) of the input units
	# to 0 at each update during training, which helps prevent overfitting.
	# Perhaps lower the rate if accuracy on the training or validation set
	# is low and increase if training set worked well but test set did not
	model.add(Dropout(0.5))
	model.add(Dense(15, activation='relu'))
	model.add(Dropout(0.5))
	model.add(Dense(1, activation='sigmoid'))
	model.compile(optimizer='rmsprop', loss='binary_crossentropy', \
		metrics=['accuracy'])
	model.fit(x_train, y_train, epochs=2000, \
		batch_size=int(pcap_duration/(step_length * 2)))
	if save_model == True:
		try:
			model.save(savefile)
		except:
			print "Couldn't save the model"
	return model

'''
Evaluates the model given x_test and y_test
Parameters:
model - model generated by create_model or loaded from h5 file
x_test - numpy array for x test set
y_test - numpy array for y test set
pcap_duration - pcap duration (seconds) - available on CTU website
step_length - step duration (seconds)
'''
def evaluate_model(model, x_test, y_test, pcap_duration, step_length):
	score = model.evaluate(x_test, y_test, \
		batch_size=int(pcap_duration/(step_length * 2)))
	loss, accuracy = score
	print "\nLoss: " + str(loss)
	print "Accuracy: " + str(accuracy * 100) + "%"

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


def main():
	step_length = 60
	interval_length = 120

	scenario = 10
	pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = get_botnet_nodes(scenario)
	pcap_duration = get_pcap_duration(scenario) # * 0.1

	x, y = generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=True, savefile_x='x.txt', savefile_y='y.txt', verbose = True)
	# x, y = load_input_arrays(filename_x='x.txt', filename_y='y.txt')
	x_train, y_train, x_test, y_test = separate_into_sets(x, y, \
		training_proportion = 0.7)

	model = create_model(x_train, y_train, pcap_duration, step_length, \
	 	save_model=True, savefile="model.h5")
	# model = load_model('model.h5')
	evaluate_model(model, x_test, y_test, pcap_duration, step_length)

main()