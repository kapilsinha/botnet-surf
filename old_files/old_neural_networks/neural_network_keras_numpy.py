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
in the pcap file. Note that this can be very time consuming for large pcap files
Parameters:
pcap_filename - Name of pcap file
do_save - True if input arrays are saved in a file
savefile_x - Name of x file
savefile_y Name of y file
'''
def generate_input_arrays(pcap_filename, botnet_nodes, pcap_duration, \
	step_length = 60, interval_length = 120, do_save=True, savefile_x='x.txt', \
	savefile_y='y.txt', verbose = True):
	pcap_graph = create_graph.PcapGraph(pcap_filename, \
		step_length = step_length, interval_length = interval_length)
	# I am not splitting the input or output values into training and testing
	# sets - I do that later
	# Input: 2D array of size (num_vertices, VECTOR_SIZE)
	x = np.array([]).reshape(0, VECTOR_SIZE)
	# Output: array of length num_vertices
	# (1 if the corresponding vertex is malicious, 0 if it is non-malicious)
	y = np.array([])

	if verbose == False:
		blockPrint()

	for i in range(int(((pcap_duration - interval_length)/step_length))):
	#i = -1
	#while pcap_graph.reached_file_end == False:
	#	i += 1
		print str(float(100 * i)/int(((pcap_duration - interval_length)/step_length))) \
			+ "%"
		g = pcap_graph.make_graph()
		print "Out-degrees..."
		outd = normalize(g.get_out_degrees(g.get_vertices()))
		print "In-degrees..."
		ind = normalize(g.get_in_degrees(g.get_vertices()))
		print "In-neighbors..."
		inn = np.array([])
		print "Out-neighbors..."
		outn = np.array([])
		for v in g.get_vertices():
			inn = np.append(inn, len(g.get_in_neighbours(v)))
			outn = np.append(outn, len(g.get_out_neighbours(v)))
		inn = normalize(inn)
		outn = normalize(outn)
		print "Pagerank..."
		pr = normalize(pagerank(g).a)
		print "Betweenness..."
		b = normalize(betweenness(g)[0].a)
		print "Closeness..."
		c = normalize(closeness(g).a)
		print "Eigenvector..."
		# this eigenvector algorithm often has a very slow convergence so I've added a max_iter
		# which makes it not get stuck here...maybe remove this metric since it doesn't seem useful
		ev = normalize(eigenvector(g, max_iter = 500)[1].a)
		print "Katz..."
		k = normalize(katz(g).a)
		print "Authority..."
		auth = normalize(hits(g)[1].a)
		print "Hub..."
		hub = normalize(hits(g)[2].a)
		print "Clustering..."
		clustering = normalize(local_clustering(g).a) # this seems to take a long time to run
		if pcap_graph.reached_file_end == True:
			print "Reached the end of the pcap file in the training phase"
			sys.exit(1)

		x = np.append(x, np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
			auth, hub, clustering]).transpose(), axis=0)

		# If the node is a Botnet node and has been infected (the graph's latest
		# timestamp is greater than the node's infection time), output is 1.
		# Else output is 0
		ip_address = np.array([])
		for v in g.vertices():
			ip_address = np.append(ip_address, g.vp.ip_address[v])
		
		y = np.append(y, np.in1d(ip_address, botnet_nodes).astype(int))
		# doesn't account for the time....
		'''
		print "Iterating over vertices..."
		for v in g.vertices():
			# Note that some measures of centrality can be NaN so I change the NaN values
			# to 0 by doing max('centrality'[v], 0)
			x = np.append(x, [[v.out_degree(), v.in_degree(), \
				len(g.get_in_neighbours(int(v))), len(g.get_out_neighbours(int(v))), \
				max(0, pr[v]), max(0, b[v]), max(0, c[v]), max(0, ev[v]), max(0, k[v]), \
				max(0, authority[v]), max(0, hub[v]), max(0, clustering[v])]], axis=0)
			# If the node is a Botnet node and has been infected (the graph's latest
			# timestamp is greater than the node's infection time), output is 1.
			# Else output is 0
			if g.vp.ip_address[v] in botnet_nodes.keys() and \
				g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]]:
				# COMMENT OUT THE TIME PORTION IF NOT TESTING ON SCENARIO 10
					y = np.append(y, 1)
			else:
				y = np.append(y, 0)
		'''
	enablePrint()

	print "# of inputs: " + str(len(x))
	print "# of outputs: " + str(len(y))
	if do_save:
		np.savetxt(savefile_x, x)
		np.savetxt(savefile_y, y)
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
def create_model(x_train, y_train, pcap_duration, step_length, save_model=True, savefile="model.h5"):
	print "Starting the creation of the model"
	model = Sequential()
	# Input arrays of shape (num_vertices, 12) and
	# output arrays of shape (num_vertices, 1)
	model.add(Dense(15, input_dim=12, activation='relu'))
	# Dropout: Randomly set half (arbitrarily chosen fraction) of the input units
	# to 0 at each update during training time, which helps prevent overfitting.
	# Perhaps lower the rate if the accuracy on the training or validation set
	# is low and increase if the training set worked well but the test set did not
	model.add(Dropout(0.5))
	model.add(Dense(15, activation='relu'))
	model.add(Dropout(0.5))
	model.add(Dense(1, activation='sigmoid'))
	model.compile(optimizer='rmsprop', loss='binary_crossentropy', metrics=['accuracy'])
	model.fit(x_train, y_train, epochs=20, batch_size=int(pcap_duration/(step_length * 2))) # epochs=2000
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
	score = model.evaluate(x_test, y_test, batch_size=int(pcap_duration/(step_length * 2)))
	loss, accuracy = score
	print "\nLoss: " + str(loss)
	print "Accuracy: " + str(accuracy * 100) + "%"

def main():
	'''
	Identifying malicious packets:
	IP Address     Name     Infection time (Time of Day)  (Seconds since epoch)
	147.32.84.165: SARUMAN  Infected at Aug 18 11:06:10 CEST 2011 -> 1313658370
	147.32.84.191: SARUMAN1 Infected at Aug 18 11:06:32 CEST 2011 -> 1313658392
	147.32.84.192: SARUMAN2 Infected at Aug 18 11:05:41 CEST 2011 -> 1313658341
	147.32.84.193: SARUMAN3 Infected at Aug 18 11:06:52 CEST 2011 -> 1313658412
	147.32.84.204: SARUMAN4 Infected at Aug 18 11:05:13 CEST 2011 -> 1313658313
	147.32.84.205: SARUMAN5 Infected at Aug 18 11:07:15 CEST 2011 -> 1313658435
	147.32.84.206: SARUMAN6 Infected at Aug 18 11:04:46 CEST 2011 -> 1313658286
	147.32.84.207: SARUMAN7 Infected at Aug 18 11:04:20 CEST 2011 -> 1313658260
	147.32.84.208: SARUMAN8 Infected at Aug 18 11:03:52 CEST 2011 -> 1313658232
	147.32.84.209: SARUMAN9 Infected at Aug 18 11:03:05 CEST 2011 -> 1313658185
	'''
	step_length = 60
	interval_length = 120
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = {"147.32.84.165": 1313658370, "147.32.84.191": 1313658392, \
	                "147.32.84.192": 1313658341, "147.32.84.193": 1313658412, \
	                "147.32.84.204": 1313658313, "147.32.84.205": 1313658435, \
	                "147.32.84.206": 1313658286, "147.32.84.207": 1313658260, \
	                "147.32.84.208": 1313658232, "147.32.84.209": 1313658185}
	pcap_duration = 17000 * 0.1 #* .58 # approximate duration of pcap capture (in seconds) of CTU-13 scenario 10
	pcap_file = sys.argv[1]

	x, y = generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=False, savefile_x='x.txt', savefile_y='y.txt', verbose = True)
	# x, y = load_input_arrays(filename_x='x.txt', filename_y='y.txt')
	x_train, y_train, x_test, y_test = separate_into_sets(x, y, \
		training_proportion = 0.7)

	model = create_model(x_train, y_train, pcap_duration, step_length, \
	 	save_model=False, savefile="model.h5")
	# model = load_model('model.h5')
	evaluate_model(model, x_test, y_test, pcap_duration, step_length)

main()