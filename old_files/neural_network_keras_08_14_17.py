import sys, os
from keras.models import Sequential, load_model
from keras.layers import Dense, Dropout
import tensorflow as tf
import numpy as np
from sklearn.metrics import roc_curve, auc
from graph_tool.all import *
import matplotlib.pyplot as plt
from random import random
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

'''
Defining a weighted mean square error. Note that I am now using TensorFlow
specific functions so that is the required backend for this code to work...
it should be easy to translate this to other backends though (I just couldn't
figure out how to use Keras to do this).
'''
def my_loss_func(y_true, y_pred):
	print y_true
	print type(y_true)
	print y_true.eval(session=tf.Session())
	weighted_y_true = np.copy(y_true)
	weighted_y_true[weighted_y_true == 1] = 250000
	print weighted_y_true
	print type(weighted_y_true)
	weighted_y_pred = np.copy(y_pred)
	weighted_y_pred[weighted_y_pred == 1] = 250000
	# Weighted mean_absolute_error ?
	#return K.mean(K.abs(weighted_y_pred - weighted_y_true), axis=-1)

	# Weighted mean squared error?
	return K.mean(K.square(weighted_y_pred - y_pred), axis=-1)

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
	#model.add(Dense(15, activation='relu'))
	#model.add(Dropout(0.5))
	#model.add(Dense(15, activation='relu'))
	#model.add(Dropout(0.5))
	model.add(Dense(1, activation='sigmoid'))
	model.compile(optimizer='rmsprop', loss='mean_squared_error', \
		metrics=['accuracy', true_positives, true_negatives, \
		false_positives, false_negatives, true_positive_rate, \
		true_negative_rate, false_positive_rate, false_negative_rate])
	model.fit(x_train, y_train, epochs=2000, \
		batch_size=int(pcap_duration/(step_length * 2)))
		#sample_weight = weights)
		# class_weight = {0.: 1., 1.: 25000})  --> doesn't do anything??
	# for scenario 12, I think there are 187 1 outputs and 466294 total outputs
	# - hence the 1:2500 class weight
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
x_test - numpy array for x test set
y_test - numpy array for y test set
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
Counts the proportion of true positives to total actual positives
'''
def true_positives(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    true_positives = K.sum(y_pos * y_pred_pos) #/ K.sum(y_pos + K.epsilon())
    return true_positives

'''
Counts the proportion of true negatives to total actual negatives
'''
def true_negatives(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    true_negatives = K.sum(y_neg * y_pred_neg) #/ K.sum(y_neg + K.epsilon())
    return true_negatives

'''
Counts the proportion of false positives to total negatives
'''
def false_positives(y_true, y_pred):
    y_pred_pos = K.round(K.clip(y_pred, 0, 1))
    y_neg = 1 - K.round(K.clip(y_true, 0, 1))
    false_positives = K.sum(y_neg * y_pred_pos) #/ K.sum(y_neg + K.epsilon())
    return false_positives

'''
Counts the proportion of false negatives to total positives
'''
def false_negatives(y_true, y_pred):
    y_pred_neg = 1 - K.round(K.clip(y_pred, 0, 1))
    y_pos = K.round(K.clip(y_true, 0, 1))
    false_negatives = K.sum(y_pos * y_pred_neg) #/ K.sum(y_pos + K.epsilon())
    return false_negatives

'''
Displays the Receiver Operator Characteristic (ROC) curve with the area
under its curve given the parameter model and x and y data arrays
'''
def generate_roc_curve(model, x_test, y_test, data_scenario, model_scenario):
	# Get array of probabilities of that the y result is a 1
	y_score = model.predict_proba(x_test)
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
	plt.savefig("roc_curves/hidden_layers_3/model_" + str(model_scenario) + "_data_" + \
		str(data_scenario) + "_hidden_layers_3.png")
	#plt.show()

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
	
	model_scenario = 9
	data_scenario = 9 # scenario 9's data has good results for several models

	#pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = get_botnet_nodes(data_scenario)
	pcap_duration = get_pcap_duration(data_scenario) # * 0.1

	savefile_x = 'Scenario_' + str(data_scenario) + '_model/' + \
		'x_scenario_' + str(data_scenario) + '.txt'
	savefile_y = 'Scenario_' + str(data_scenario) + '_model/' + \
		'y_scenario_' + str(data_scenario) + '.txt'
	model_savefile = 'Scenario_' + str(model_scenario) + '_model/' + \
		'model_scenario_' + str(model_scenario) + '_hidden_layers_3.h5'
	
	'''
	x, y = generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=True, savefile_x=savefile_x, savefile_y=savefile_y, verbose = True)
	'''
	x, y = load_input_arrays(filename_x=savefile_x, filename_y=savefile_y)
	
	'''
	x_train, y_train, x_test, y_test = separate_into_sets(x, y, \
		training_proportion = 0.7)
	'''
	balanced_savefile_x, balanced_savefile_y = \
		balance_data(savefile_x, savefile_y)
	balanced_x, balanced_y = load_input_arrays(filename_x=balanced_savefile_x, \
		filename_y=balanced_savefile_y)
	# Note that the test set contains all the data so obviously it includes the
	# training data...since the training data is so limited, it likely will have
	# little effect on the outcome though
	_, _, x_test, y_test = separate_into_sets(x, y, training_proportion = 0)
	x_train, y_train, _, _ = \
		separate_into_sets(balanced_x, balanced_y, training_proportion = 0.7)

	weighted_y_train = np.copy(y_train)
	weighted_y_train[weighted_y_train == 1] = 3.5
	weighted_y_test = np.copy(y_test)
	weighted_y_test[weighted_y_test == 1] = 3.5
	# TEMPORARY: I AM APPLYING MY WEIGHTS HERE INSTEAD OF IN A CUSTOM LOSS FUNCTION
	# (WHICH IS PROBABLY MORE CORRECT); CHANGE THIS LATER

	"""
	model = create_model(x_train, weighted_y_train, pcap_duration, step_length, \
	 	save_model=True, savefile=model_savefile)
	"""
	model = load_model(model_savefile, custom_objects = \
		{'true_positives': true_positives, 'false_positives': false_positives, \
		 'true_negatives': true_negatives, 'false_negatives': false_negatives})
	evaluate_model(model, x_test, y_test, pcap_duration, step_length)
	generate_roc_curve(model, x_test, y_test, data_scenario, model_scenario)

main()