import sys
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.models import load_model
import numpy as np
import create_graph
from graph_tool.all import *
import h5py

"""
Vertex features - all 12 of these are calculated using graph-tool's functions:
["Out-degree", "In-degree", "# of in-neighbors", "# of out-neighbors", 
 "Page Rank", "Betweenness", "Closeness", "Eigenvector", "Katz",
 "Authority centrality", "Hub centrality", "Clustering coefficient"]
The above features will be normalized and placed in a vector for each vertex
in each time interval

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
"""
'''
Returns a numpy array of size VECTOR_SIZE given the graph g and vertex v
'''

VECTOR_SIZE = 12 # number of vertex characteristics in the vector
# Dictionary of malicious IP addresses with start timestamp as its value
botnet_nodes = {"147.32.84.165": 1313658370, "147.32.84.191": 1313658392, \
                "147.32.84.192": 1313658341, "147.32.84.193": 1313658412, \
                "147.32.84.204": 1313658313, "147.32.84.205": 1313658435, \
                "147.32.84.206": 1313658286, "147.32.84.207": 1313658260, \
                "147.32.84.208": 1313658232, "147.32.84.209": 1313658185}
# The step and interval lengths are this small for testing purposes - change them to 150, 300
step_length = 15
interval_length = 30

pcap_duration = 17000 * .58 # approximate duration of pcap capture (in seconds) of CTU-13 scenario 10
'''
filename = sys.argv[1]
pcap_graph = create_graph.PcapGraph(filename, step_length = step_length, \
	interval_length = interval_length)

# Input: 2D array of size (num_vertices, VECTOR_SIZE)
x_train = np.array([]).reshape(0, VECTOR_SIZE)
# Output: array of length num_vertices
# (1 if the corresponding vertex is malicious, 0 if it is non-malicious)
y_train = np.array([])
x_test = np.array([]).reshape(0, VECTOR_SIZE)
y_test = np.array([])

# Loop over approximately 70% of the steps in the pcap file
for i in range(int(((pcap_duration - interval_length)/step_length) * 0.7)):
	print str(float(100 * i)/int(((pcap_duration - interval_length)/step_length))) \
		+ "%"
	g = pcap_graph.make_graph()
	print 1
	pr = pagerank(g)
	print 2
	b = betweenness(g)[0]
	print 3
	c = closeness(g)
	print 4
	# ev = eigenvector(g)[1] # for some reason, it is getting stuck here in a random iteration
	print 5
	k = katz(g)
	print 6
	authority = hits(g)[1]
	print 7
	hub = hits(g)[2]
	print 8
	clustering = local_clustering(g)
	print 9
	if pcap_graph.reached_file_end == True:
		print "Reached the end of the pcap file in the training phase"
		sys.exit(1)
	for v in g.vertices():
		# Note that some measures of centrality can be NaN so I change the NaN values
		# to 0 by doing max('centrality'[v], 0)
		x_train = np.append(x_train, [[v.out_degree(), v.in_degree(), \
			len(g.get_in_neighbours(int(v))), len(g.get_out_neighbours(int(v))), \
			max(0, pr[v]), max(0, b[v]), max(0, c[v]), max(0, c[v]), max(0, k[v]), \
			max(0, authority[v]), max(0, hub[v]), max(0, clustering[v])]], axis=0)
		# If the node is a Botnet node and has been infected (the graph's latest
		# timestamp is greater than the node's infection time), output is 1.
		# Else output is 0
		if g.vp.ip_address[v] in botnet_nodes.keys() and \
			g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]]:
			# COMMENT OUT THE TIME PORTION IF NOT TESTING ON SCENARIO 10
				y_train = np.append(y_train, 1)
		else:
			y_train = np.append(y_train, 0)

i = int(((pcap_duration - interval_length)/step_length) * 0.7)
while pcap_graph.reached_file_end == False:
#for i in range(int(((pcap_duration - interval_length)/step_length) * 0.3)):
	print str(float(100 * i)/int(((pcap_duration - interval_length)/step_length))) \
		+ "%"
	i += 1
	g = pcap_graph.make_graph()
	print 1
	pr = pagerank(g)
	print 2
	b = betweenness(g)[0]
	print 3
	c = closeness(g)
	print 4
	# ev = eigenvector(g)[1] # for some reason, it is getting stuck here in a random iteration
	print 5
	k = katz(g)
	print 6
	authority = hits(g)[1]
	print 7
	hub = hits(g)[2]
	print 8
	clustering = local_clustering(g)
	print 9
	for v in g.vertices():
		x_test = np.append(x_test, [[v.out_degree(), v.in_degree(), \
			len(g.get_in_neighbours(int(v))), len(g.get_out_neighbours(int(v))), \
			max(0, pr[v]), max(0, b[v]), max(0, c[v]), max(0, c[v]), max(0, k[v]), \
			max(0, authority[v]), max(0, hub[v]), max(0, clustering[v])]], axis=0)
		# If the node is a Botnet node and has been infected (the graph's latest
		# timestamp is greater than the node's infection time), output is 1.
		# Else output is 0
		if g.vp.ip_address[v] in botnet_nodes.keys() and \
			g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]]:
			# COMMENT OUT THE TIME PORTION IF NOT TESTING ON SCENARIO 10
				y_test = np.append(y_test, 1)
		else:
			y_test = np.append(y_test, 0)

print len(x_train)
print len(y_train)
print len(x_test)
print len(y_test)
print "Finished creating the input file. Training in progress."
np.savetxt('x_train.txt', x_train)
np.savetxt('y_train.txt', y_train)
np.savetxt('x_test.txt', x_test)
np.savetxt('y_test.txt', y_test)
'''
x_train = np.loadtxt('x_train.txt')
y_train = np.loadtxt('y_train.txt')
x_test = np.loadtxt('x_test.txt')
y_test = np.loadtxt('y_test.txt')


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
model.fit(x_train, y_train, epochs=20, batch_size=int(pcap_duration/(step_length * 2)))
score = model.evaluate(x_test, y_test, batch_size=int(pcap_duration/(step_length * 2)))
loss, accuracy = score
print "\nLoss: " + str(loss * 100) + "%"
print "Accuracy: " + str(accuracy * 100) + "%"

try:
	model.save('first_model.h5') # model = load_model('first_model.h5')
except:
	print "Couldn't save the model"