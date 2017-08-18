import numpy as np
from random import random
from graph_tool.all import *
import create_graph
import scenario_info

"""
Vertex features - first 12 of these are calculated using graph-tool's functions
and the remaining 16 are my calculations of 'function' features - i.e. similar
to flow features but per node instead of per flow
["Out-degree", "In-degree", "# of in-neighbors", "# of out-neighbors", 
 "Page Rank", "Betweenness", "Closeness", "Eigenvector", "Katz",
 "Authority centrality", "Hub centrality", "Clustering coefficient", 
 "Average incoming packet size", "Max incoming packet size,"
 "Min incoming packet size", "Average outgoing packet size",
 "Max outgoing packet size", "Min outgoing packet size", "Number incoming bytes", 
 "Number outgoing bytes", "Number source ports", "Number destination ports",
 "Average incoming TTL", "Max incoming TTL", "Min incoming TTL", 
 "Average outgoing TTL", "Max outgoing TTL", "Min outgoing TTL"]
The above features will be normalized and placed in a vector for each vertex
in each time interval
"""
VECTOR_SIZE = 28 # number of vertex characteristics in the vector

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

        print "Extra 'function' features..."
        # Dictionaries containing vertex indices as keys and lists of their 
        # corresponding values -> used to calculate the "function" features
        incoming_packet_size = {} # in number of bytes
        outgoing_packet_size = {}
        source_ports = {} # unique source ports the host is receiving messages from
        dest_ports = {} # unique destination ports the host is sending messages to
        source_ttl = {} # outgoing packets' TTLs
        dest_ttl = {} # incoming packets' TTLs
        for v in g.get_vertices():
            incoming_packet_size[v] = []
            outgoing_packet_size[v] = []
            source_ports[v] = []
            dest_ports[v] = []
            source_ttl[v] = []
            dest_ttl[v] = []

        # I could iterate over the in and out edges per vertex - which could
        # probably save some RAM. But this will make it faster...
        for e in g.edges():
            port_source = g.ep.port_source[e]
            port_dest = g.ep.port_dest[e]
            ttl = g.ep.ttl[e]
            num_bytes = g.ep.num_bytes[e]
            incoming_packet_size[e.target()].append(num_bytes)
            outgoing_packet_size[e.source()].append(num_bytes)
            source_ports[e.target()].append(port_source)
            dest_ports[e.source()].append(port_dest)
            source_ttl[e.source()].append(ttl)
            dest_ttl[e.target()].append(ttl)

        # I don't like that I'm adding so many Python loops (it'll make things
        # slow) but we'll see how it goes
        avg_incoming_packet_size, max_incoming_packet_size, \
            min_incoming_packet_size = np.array([]), np.array([]), np.array([])
        avg_outgoing_packet_size, max_outgoing_packet_size, \
            min_outgoing_packet_size = np.array([]), np.array([]), np.array([])
        number_incoming_bytes, number_outgoing_bytes \
            = np.array([]), np.array([])
        number_source_ports, number_dest_ports = np.array([]), np.array([])
        avg_incoming_ttl, max_incoming_ttl, min_incoming_ttl \
            = np.array([]), np.array([]), np.array([])
        avg_outgoing_ttl, max_outgoing_ttl, min_outgoing_ttl \
            = np.array([]), np.array([]), np.array([])
        for v in g.get_vertices():
            if len(incoming_packet_size[v]) > 0:
                # and len(set(source_ports[v])) > 0 and len(dest_ttl[v]) > 0
                # All the above conditions are equivalent because of the way we
                # add to these lists (see the loop over the edges -> line 177)
                avg_incoming_packet_size = np.append(avg_incoming_packet_size, \
                    sum(incoming_packet_size[v])/len(incoming_packet_size[v]))
                max_incoming_packet_size = np.append(max_incoming_packet_size, \
                    max(incoming_packet_size[v]))
                min_incoming_packet_size = np.append(min_incoming_packet_size, \
                    min(incoming_packet_size[v]))
                number_incoming_bytes = np.append(number_incoming_bytes, \
                    sum(incoming_packet_size[v]))
                number_source_ports = np.append(number_source_ports, \
                    len(set(source_ports[v])))
                avg_incoming_ttl = np.append(avg_incoming_ttl, \
                    sum(dest_ttl[v])/len(dest_ttl[v]))
                max_incoming_ttl = np.append(max_incoming_ttl, \
                    max(dest_ttl[v]))
                min_incoming_ttl = np.append(min_incoming_ttl, 
                    min(dest_ttl[v]))
            # If there are no incoming packets, pad with 0s
            else:
                avg_incoming_packet_size = np.append(avg_incoming_packet_size, 0)
                max_incoming_packet_size = np.append(max_incoming_packet_size, 0)
                min_incoming_packet_size = np.append(min_incoming_packet_size, 0)
                number_incoming_bytes = np.append(number_incoming_bytes, 0)
                number_source_ports = np.append(number_source_ports, 0)
                avg_incoming_ttl = np.append(avg_incoming_ttl, 0)
                max_incoming_ttl = np.append(max_incoming_ttl, 0)
                min_incoming_ttl = np.append(min_incoming_ttl, 0)
            
            if len(outgoing_packet_size[v]) > 0:
                # and len(set(dest_ports[v]) > 0 and len(source_ttl[v]) > 0
                # All the above conditions are equivalent because of the way we
                # add to these lists (see the loop over the edges -> line 177)
                avg_outgoing_packet_size = np.append(avg_outgoing_packet_size, \
                    sum(outgoing_packet_size[v])/len(outgoing_packet_size[v]))
                max_outgoing_packet_size = np.append(max_outgoing_packet_size, \
                    max(outgoing_packet_size[v]))
                min_outgoing_packet_size = np.append(min_outgoing_packet_size, \
                    min(outgoing_packet_size[v]))
                number_outgoing_bytes = np.append(number_outgoing_bytes, \
                    sum(outgoing_packet_size[v]))
                number_dest_ports = np.append(number_dest_ports, \
                    len(set(dest_ports[v])))
                avg_outgoing_ttl = np.append(avg_outgoing_ttl, \
                    sum(source_ttl[v])/len(source_ttl[v]))
                max_outgoing_ttl = np.append(max_outgoing_ttl, \
                    max(source_ttl[v]))
                min_outgoing_ttl = np.append(min_outgoing_ttl, \
                    min(source_ttl[v]))
            # If there are no outgoing packets, pad with 0s
            else:
                avg_outgoing_packet_size = np.append(avg_outgoing_packet_size, 0)
                max_outgoing_packet_size = np.append(max_outgoing_packet_size, 0)
                min_outgoing_packet_size = np.append(min_outgoing_packet_size, 0)
                number_outgoing_bytes = np.append(number_outgoing_bytes, 0)
                number_dest_ports = np.append(number_dest_ports, 0)
                avg_outgoing_ttl = np.append(avg_outgoing_ttl, 0)
                max_outgoing_ttl = np.append(max_outgoing_ttl, 0)
                min_outgoing_ttl = np.append(min_outgoing_ttl, 0)
            
        avg_incoming_packet_size = normalize(avg_incoming_packet_size)
        max_incoming_packet_size = normalize(max_incoming_packet_size)
        min_incoming_packet_size = normalize(min_incoming_packet_size)
        avg_outgoing_packet_size = normalize(avg_outgoing_packet_size)
        max_outgoing_packet_size = normalize(max_outgoing_packet_size)
        min_outgoing_packet_size = normalize(min_outgoing_packet_size)
        number_incoming_bytes = normalize(number_incoming_bytes)
        number_outgoing_bytes = normalize(number_outgoing_bytes)
        number_source_ports = normalize(number_source_ports)
        number_dest_ports = normalize(number_dest_ports)

        avg_incoming_ttl = normalize(avg_incoming_ttl)
        max_incoming_ttl = normalize(max_incoming_ttl)
        min_incoming_ttl = normalize(min_incoming_ttl)
        avg_outgoing_ttl = normalize(avg_outgoing_ttl)
        max_outgoing_ttl = normalize(max_outgoing_ttl)
        min_outgoing_ttl = normalize(min_outgoing_ttl)
        # this seems to take a long time to run
        print "Appending to x..."
        x = np.append(x, np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
            auth, hub, clustering, avg_incoming_packet_size, \
            max_incoming_packet_size, min_incoming_packet_size, \
            avg_outgoing_packet_size, max_outgoing_packet_size, \
            min_outgoing_packet_size, number_incoming_bytes, \
            number_outgoing_bytes, number_source_ports, number_dest_ports, \
            avg_incoming_ttl, max_incoming_ttl, min_incoming_ttl, \
            avg_outgoing_ttl, max_outgoing_ttl, max_outgoing_ttl]) \
            .transpose(), axis=0)
        
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
