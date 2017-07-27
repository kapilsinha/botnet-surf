import sys, os
from keras.models import Sequential, load_model
from keras.layers import Dense, Dropout, LSTM, Flatten
import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt
from random import random
from sklearn.metrics import roc_curve, auc
from graph_tool.all import *
import create_graph
from metrics import *

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
	return new_x, new_y

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
			" positive cases will be included in the training sets"
		print str(positive_count - included_positives), \
			" positive cases will be included in the testing sets"
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

'''
Trains the model
Parameters:
x_train - NumPy array for x training set
y_train - NumPy array for y training set
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
	# len(x_train) = number of samples/vertices
	# len(x_train[0]) = number of time_steps/graphs,
	# len(x_train[0][0]) = number of features
	'''
	# Adding batch size screws up the program since it has to match batch
	# size later...it's necessary for stateful LSTM but not for stateless
	model.add(LSTM(32, batch_input_shape=(len(x_train), len(x_train[0]), \
		len(x_train[0][0])), return_sequences=True, stateful=False))
	'''
	# Dropout: Randomly set half (arbitrarily fraction) of the input units
	# to 0 at each update during training, which helps prevent overfitting.
	# Perhaps lower the rate if accuracy on the training or validation set
	# is low and increase if training set worked well but test set did not
	
	# One layer:
	model.add(LSTM(64, input_shape=(len(x_train[0]), \
		len(x_train[0][0])), return_sequences=True, stateful=False))
	model.add(Flatten())
	model.add(Dense(1, activation='sigmoid'))
	
	"""
	# Two layers:
	model.add(LSTM(64, input_shape=(len(x_train[0]), \
		len(x_train[0][0])), return_sequences=True, stateful=False))
	model.add(Dropout(0.5))
	model.add(LSTM(64))
	model.add(Dense(1, activation='sigmoid'))
	"""
	"""
	# Three layers:
	model.add(LSTM(64, input_shape=(len(x_train[0]), \
		len(x_train[0][0])), return_sequences=True, stateful=False))
	model.add(Dropout(0.5))
	model.add(LSTM(64, return_sequences=True))
	model.add(Dropout(0.5))
	model.add(LSTM(64))
	model.add(Dropout(0.5))
	model.add(Dense(1, activation='sigmoid'))
	"""

	model.compile(optimizer='rmsprop', loss='mean_squared_error', \
		metrics=['accuracy', true_positives, true_negatives, \
		false_positives, false_negatives, true_positive_rate, \
		true_negative_rate, false_positive_rate, false_negative_rate])
	model.fit(x_train, y_train, epochs=200, \
		batch_size=int(pcap_duration/(step_length * 2)), shuffle = False)

	if save_model == True:
		try:
			model.save(savefile)
			print "Saved model as " + str(savefile)
		except:
			print "Couldn't save the model"
	return model

'''
Evaluates the model given x_test and y_test
Parameters:
model - model generated by create_model or loaded from h5 file
x_test - NumPy array for x test set
y_test - NumPy array for y test set
pcap_duration - pcap duration (seconds) - available on CTU website
step_length - step duration (seconds)
'''
def evaluate_model(model, x_test, y_test, pcap_duration, step_length):
	score = model.evaluate(x_test, y_test, \
		batch_size=int(pcap_duration/(step_length * 2)))
	loss, accuracy, true_positives, true_negatives, false_positives, \
		false_negatives, true_positive_rate, true_negative_rate, \
		false_positive_rate, false_negative_rate = score
	print "\n"
	print "Loss: " + str(loss)
	print "Accuracy: " + str(accuracy * 100) + "%"
	print "True positives: " + str(true_positives)
	print "True positive rate: " + str(true_positive_rate * 100) + "%"
	print "True negatives: " + str(true_negatives)
	print "True negative rate: " + str(true_negative_rate * 100) + "%"
	print "False positives: " + str(false_positives)
	print "False positive rate: " + str(false_positive_rate * 100) + "%"
	print "False negatives: " + str(false_negatives)
	print "False negative rate: " + str(false_negative_rate * 100) + "%"

'''
Displays the Receiver Operator Characteristic (ROC) curve with the area
under its curve given the parameter model and x and y data arrays
'''
def generate_roc_curve(model, x_test, y_test, data_scenario, model_scenario):
	# Get array of probabilities of that the y result is a 1
	y_score = model.predict_proba(x_test) # THIS  LINE CAUSES THE STATEFUL LSTM TO FAIL
	# Compute ROC curve and ROC area for each class
	fpr, tpr, _ = roc_curve(y_test, y_score)
	roc_auc = auc(fpr, tpr)
	plt.figure()
	plt.plot(fpr, tpr, color='darkorange',
	         lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
	plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
	plt.xlim([0.0, 1.0])
	plt.ylim([0.0, 1.05])
	plt.xlabel('False Positive Rate')
	plt.ylabel('True Positive Rate')
	plt.title('Receiver operating characteristic of scenario ' \
		+ str(model_scenario) + '\'s model on scenario ' \
		+ str(data_scenario) + '\'s data')
	plt.legend(loc="lower right")
	#plt.savefig("roc_curves/model_" + str(model_scenario) + "_data_" + \
	#	str(data_scenario) + ".png")
	plt.show()

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
	step_length = 15
	interval_length = 60
	
	model_scenario = 11
	data_scenario = 11 # scenario 9's data has good results for several models`

	# pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = get_botnet_nodes(data_scenario)
	pcap_duration = get_pcap_duration(data_scenario) # * 0.1

	savefile_x = 'lstm_inputs/x_scenario_' + str(data_scenario) + '_lstm.txt'
	savefile_y = 'lstm_inputs/y_scenario_' + str(data_scenario) + '_lstm.txt'
	model_savefile = 'lstm_model_scenario_' + str(model_scenario) + '.h5'

	'''
	x, y = generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=True, savefile_x=savefile_x, savefile_y=savefile_y, verbose = True)
	'''
	x, y = load_input_arrays(filename_x=savefile_x, filename_y=savefile_y)
	x, y = time_window_data(x, y, 5, 2)
	'''
	x_train, y_train, x_test, y_test = separate_into_sets(x, y, \
		training_proportion = 0.7)
	'''
	balanced_x, balanced_y = balance_data(x, y, ratio = 10)
	# Note that the test set contains all the data so obviously it includes the
	# training data...since the training data is so limited, it likely will have
	# little effect on the outcome though
	'''
	_, _, x_test, y_test = separate_into_sets(x, y, training_proportion = 0)
	x_train, y_train, _, _ = \
		separate_into_sets(balanced_x, balanced_y, training_proportion = 0.7)
	'''
	x_train, y_train, x_test, y_test = \
		separate_into_sets(balanced_x, balanced_y, positive_proportion = 0.5)
	print x.shape, y.shape
	print x_test.shape, y_test.shape
	print x_train.shape, y_train.shape

	weighted_y_train = np.copy(y_train)
	weighted_y_train[weighted_y_train == 1] = 6
	weighted_y_test = np.copy(y_test)
	weighted_y_test[weighted_y_test == 1] = 6
	# TEMPORARY: I AM APPLYING MY WEIGHTS HERE INSTEAD OF IN A CUSTOM LOSS FUNCTION
	# (WHICH IS PROBABLY MORE CORRECT); CHANGE THIS LATER
	model = create_model(x_train, weighted_y_train, pcap_duration, step_length, \
	 	save_model=True, savefile=model_savefile)
	
	"""
	model = load_model(model_savefile, custom_objects = \
		{'true_positives': true_positives, 'false_positives': false_positives, \
		 'true_negatives': true_negatives, 'false_negatives': false_negatives})
	"""
	evaluate_model(model, x_test, y_test, pcap_duration, step_length)
	generate_roc_curve(model, x_test, y_test, data_scenario, model_scenario)

main()
