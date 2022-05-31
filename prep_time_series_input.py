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
VECTOR_SIZE = 28

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
Creates undersampled x and y arrays and returns them
Parameters:
x - x NumPy array
y - y NumPy array
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
Helper function that calculates the value of y given the scenario number,
and window start and end times.
If a botnet node's window start and end times are before time of infection,
then y = 0 (non-malicious). Obviously if the window start and end times
are after time of infection, then y = 1 (malicious).
Note: I don't have access to the IP addresses of nodes at this point so I
can't retrieve the exact time of infection for the nodes; thus I will simply
use the earliest time of infection of all the botnet nodes (not ideal but 
should work more or less).
Note: I don't really know what to do for windows that contain the start 
and/or end time - mark it as malicious or non-malicious or neither? Though
doing neither may be the most correct approach, this will be difficult to deal
with since I am dealing with binary classification and need to keep shapes of
these arrays constant. For now I'll treat it as malicious (can experiment later)
Parameters:
sample_y - 1 if the node is a botnet node (infected at some point), else 0
scenario - CTU dataset number
window_start_time - time (seconds since epoch) that the window started
window_end_time - time (seconds since epoch) that the window ended
'''
def calculate_y(sample_y, scenario, window_start_time, window_end_time):
    # If the node is never infected, it is always non-malicious
    if sample_y == 0:
        return 0
    # assert window_start_time < window_end_time
    infection_time = min(scenario_info.get_botnet_nodes(scenario).values())
    if window_start_time < infection_time and window_end_time < infection_time:
        return 0
    elif window_start_time < infection_time and window_end_time > infection_time:
        return 1 # I can experiment with this value
    else: # if window_start_time > infection_time and window_end_time > infection_time
        return 1

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
interval_length - number of seconds in each interval (in the graph)
step_length - number of seconds stepped between intervals (in the graph)
scenario - CTU 13 scenario number
'''
def time_window_data(x, y, window_num_steps, window_step_size, interval_length, \
        step_length, scenario):
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
    window_start_time = scenario_info.get_capture_start_time(scenario)
    window_end_time = window_start_time + interval_length + step_length * window_num_steps
    for i in range(len(new_x)):
        new_x[i] = x[j][k:l]
        new_y[i] = calculate_y(y[j], scenario, window_start_time, window_end_time) # y[j]
        if l == len(x[j]): # reset variables for the next sample
            k, l = 0, window_num_steps
            j += 1
            window_start_time = scenario_info.get_capture_start_time(scenario)
            window_end_time = window_start_time + interval_length + step_length * window_num_steps
        elif l + window_step_size > len(x[j]): # go to the last step in the sample
            k, l = len(x[j]) - window_num_steps, len(x[j])
            window_start_time = scenario_info.get_capture_start_time(scenario) \
                + k * step_length
            window_end_time = scenario_info.get_capture_start_time(scenario) \
                + interval_length + l * step_length
        else: # regular step in the same sample
            k += window_step_size
            l += window_step_size
            # The following should be equivalent
            # window_start_time += step_length * window_step_size
            window_start_time = scenario_info.get_capture_start_time(scenario) \
                + k * step_length
            # window_end_time = window_start_time + interval_length + step_length * window_num_steps
            window_end_time = scenario_info.get_capture_start_time(scenario) \
                + interval_length + l * step_length
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

        print "Adding to dict_x..."
        temp = np.array([outd, ind, inn, outn, pr, b, c, ev, k, \
            auth, hub, clustering, avg_incoming_packet_size, \
            max_incoming_packet_size, min_incoming_packet_size, \
            avg_outgoing_packet_size, max_outgoing_packet_size, \
            min_outgoing_packet_size, number_incoming_bytes, \
            number_outgoing_bytes, number_source_ports, number_dest_ports, \
            avg_incoming_ttl, max_incoming_ttl, min_incoming_ttl, \
            avg_outgoing_ttl, max_outgoing_ttl, min_outgoing_ttl]).transpose()
        
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
            with open(savefile_x.split('.')[0] + str('_dict.txt'), 'w') as f:
                f.write(str(dict_x))
                print "Saved dict_x"
        """
        """

    print "Adding to dict_y..."
    for key in dict_x.keys():
        dict_y[key] = int(key in botnet_nodes.keys())
            #and g.gp.latest_timestamp > botnet_nodes[g.vp.ip_address[v]])
    if do_save:
        with open(savefile_y.split('.')[0] + str('_dict.txt'), 'w') as f:
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
