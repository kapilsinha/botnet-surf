from graphics import * # graphics is a file I found online that uses Tkinter
import numpy as np
import random

HORIZONTAL_SCALING_FACTOR = 29
VERTICAL_SCALING_FACTOR = 35
height = int(sys.argv[1])
length = int(sys.argv[2])

with open("cluster_transitions_" + str(height) + "_" + str(length) + ".txt", \
        "r") as input:
	arr = eval(input.readline())
# List of the form [[clusters containing botnets] * time intervals]
with open("botnet_clusters_" + str(height) + "_" + str(length) + ".txt", \
        "r") as input:
	botnet_clusters = eval(input.readline())
with open("scenario_11_som_" + str(height) + "_" + str(length) + \
		"_clusters.txt", "r") as f:
	clusters = eval(f.readline())

clusters = [] # 2-D array of the form [[unique clusters] * time intervals]
for time_interval_transition in arr:
	current_clusters = []
	for cluster_transition in time_interval_transition:
		current_clusters.append(cluster_transition[0])
	current_clusters = list(set(current_clusters)) # unique clusters
	current_clusters.sort()
	clusters.append(current_clusters)
current_clusters = []
for cluster_transition in arr[-1]:
	current_clusters.append(cluster_transition[1])
current_clusters = list(set(current_clusters)) # unique clusters
current_clusters.sort()
clusters.append(current_clusters)

win = GraphWin('Visualization', 2000, 1000)
max_cluster = 0
colors = {} # cluster mapped to a color
for interval in clusters:
	for cluster in interval:
		if cluster > max_cluster:
			max_cluster = cluster
for cluster in range(1, max_cluster + 1):
	label = Text(Point(HORIZONTAL_SCALING_FACTOR * 0.4, \
		VERTICAL_SCALING_FACTOR * cluster), str(cluster))
	label.draw(win)
	colors[cluster] = color_rgb(random.randrange(50, 206), \
		random.randrange(50, 206), random.randrange(50, 206))
for time_interval in range(1, len(clusters) + 1):
	label = Text(Point(HORIZONTAL_SCALING_FACTOR * time_interval, \
		VERTICAL_SCALING_FACTOR * 0.4), str(time_interval))
	label.draw(win)

# list of dictionaries (one for each time interval) mapping cluster numbers
# to Point instances
clusters_point_array = []
for time_interval in range(len(clusters)):
	current_cluster_points = {}
	for cluster in clusters[time_interval]:
		pt = Point(HORIZONTAL_SCALING_FACTOR \
			* (time_interval + 1), VERTICAL_SCALING_FACTOR * cluster)
		current_cluster_points[cluster] = pt
		cir = Circle(pt, HORIZONTAL_SCALING_FACTOR / 6)
		cir.setOutline(colors[cluster])
		if cluster in botnet_clusters[time_interval]:
			cir.setFill('red')
		cir.draw(win)
	clusters_point_array.append(current_cluster_points)

for time_interval_transition in range(len(arr)):
	num_transitions_list = []
	# Maximum number of transitions in a line given the filters applied in the
	# loop below next - i.e. cluster_1 != cluster_2 and cluster_2 != 1 or 2
	max_filtered_transitions = 0
	total_num_transitions = 0
	for cluster_transition in arr[time_interval_transition]:
		number_transitions = cluster_transition[2]
		if cluster_transition[0] != cluster_transition[1] \
			and cluster_transition[1] not in [1,2]:
			max_filtered_transitions = max(max_filtered_transitions, number_transitions)
		num_transitions_list.append(number_transitions)
		total_num_transitions += number_transitions
	num_transitions_list.sort()
	for cluster_transition in arr[time_interval_transition]:
		cluster_1 = cluster_transition[0]
		cluster_2 = cluster_transition[1]
		number_transitions = cluster_transition[2]
		'''
		if number_transitions in num_transitions_list[- len(num_transitions_list)/2:]:
			continue
		'''
		if cluster_1 == cluster_2:
			continue
		if cluster_2 == 1 or cluster_2 == 2:
			continue
		l = Line(clusters_point_array[time_interval_transition][cluster_1], \
			clusters_point_array[time_interval_transition + 1][cluster_2])
		color = 255 - min(1, np.power(float(number_transitions)/max_filtered_transitions, 1/4.0)) * 255
		print "Num transitions: ", str(number_transitions)
		print "Max transitions: ", str(max_filtered_transitions)
		print "Color: ", str(color)
		l.setOutline(color_rgb(color, color, color))
		# l.setWidth(1 + number_transitions/max_filtered_transitions * 2)
		l.setWidth(np.log2(2 + number_transitions/max_filtered_transitions * 6))
		if cluster_1 in botnet_clusters[time_interval_transition] \
			and cluster_2 in botnet_clusters[time_interval_transition + 1]:
			l.setOutline('red')
			l.setWidth(4)
			l.draw(win)
			continue
		'''
		if cluster_1 == 2 or cluster_2 == 2:
			continue
		'''
		l.draw(win)

raw_input("\nClick enter to exit the program...")
sys.exit(0)
