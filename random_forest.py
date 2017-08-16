import sys, os
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.externals import joblib # save models
import numpy as np
'''
import matplotlib.pyplot as plt
from random import random
from sklearn.metrics import roc_curve, auc
from graph_tool.all import *
'''
import prep_input
import scenario_info

def main():
	step_length = 60
	interval_length = 120
	
	model_scenario = 11
	data_scenario = 11

	# pcap_file = sys.argv[1]
	# Dictionary of malicious IP addresses with start timestamp as its value
	botnet_nodes = scenario_info.get_botnet_nodes(data_scenario)
	pcap_duration = scenario_info.get_pcap_duration(data_scenario) # * 0.1

	savefile_x = 'neural_net_inputs/Scenario_' + str(data_scenario) + '_model/' + \
		'x_scenario_' + str(data_scenario) + '.txt'
	savefile_y = 'neural_net_inputs/Scenario_' + str(data_scenario) + '_model/' + \
		'y_scenario_' + str(data_scenario) + '.txt'
	
	'''
	x, y = prep_input.generate_input_arrays(pcap_file, botnet_nodes, pcap_duration, \
		step_length = step_length, interval_length = interval_length, \
		do_save=True, savefile_x=savefile_x, savefile_y=savefile_y, verbose = True)
	'''

	'''
	'''
	x, y = prep_input.load_input_arrays(filename_x=savefile_x, filename_y=savefile_y)
	balanced_savefile_x, balanced_savefile_y = \
		prep_input.balance_data(savefile_x, savefile_y, ratio=10)

	balanced_x, balanced_y = prep_input.load_input_arrays(filename_x=balanced_savefile_x, \
		filename_y=balanced_savefile_y)
	# Note that the test set contains all the data so obviously it includes the
	# training data...since the training data is so limited, it likely will have
	# little effect on the outcome though
	clf = RandomForestClassifier(n_estimators=100, # number of trees
		criterion="gini", # Gini impurity ("gini") or information gain ("entropy")
		max_features="sqrt", # integer, percentage, log2, or None (= n_features)
		n_jobs=-1,  # use all cores available (parallelize the task)
		bootstrap=True, class_weight="balanced_subsample", #{0: 1, 1: 10}, # weight malicious nodes by 10
		# Default options:
		max_depth=None, min_samples_split=2, min_samples_leaf=1, min_weight_fraction_leaf=0.0,
		oob_score=True, random_state=None, verbose=0, warm_start=False,
		max_leaf_nodes=None, min_impurity_split=0)
		# I NEED TO FIGURE OUT HOW TO BOOTSTRAP WITH ALL THE SAMPLES (NOT REMOVE MAJORITY CLASS MEMBERS
		# AND INSTEAD MAKE SURE THAT EACH BOOSTRAP SAMPLE CONTAINS POSITIVE SAMPLES)
		# WHAT IS THE BOOTSTRAP SIZE ANYWAY??
	print "Fitting the data..."
	clf.fit(x,y)
	joblib.dump(clf, 'scenario_' + str(model_scenario) + '_random_forest.pkl')
	# clf = joblib.load('scenario_' + str(model_scenario) + '_random_forest.pkl') 
	
	print "Evaluating the model..."
	scores = cross_val_score(clf, x, y)
	print "Scores: ", str(scores)
	print "Mean score: ", str(scores.mean())
	# print "Estimators: ", str(clf.estimators_)
	print "Classes: ", str(clf.classes_)
	print "Number of classes: ", str(clf.n_classes_)
	print "Number of features: ", str(clf.n_features_)
	print "Number of outputs: ", str(clf.n_outputs_)
	print "Feature importances: ", str(clf.feature_importances_)
	print "Oob score: ", str(clf.oob_score_)
	print "Oob decision function: ", str(clf.oob_decision_function_)

	pred = np.array([]) # contains predicted y values
	# If decision function gives >= 0.5 probability that it is 1, predicted value is a 1
	last_printed_percent = 0
	for i in range(len(clf.oob_decision_function_)):
		if float(i)/len(clf.oob_decision_function_) * 100 > last_printed_percent + 1:
			print str(float(i)/len(clf.oob_decision_function_) * 100) + "%"
			last_printed_percent = float(i)/len(clf.oob_decision_function_) * 100
		if clf.oob_decision_function_[i][1] >= 0.5:
			pred = np.append(pred, 1)
		else:
			pred = np.append(pred, 0)

	true_positives, false_positives, true_negatives, false_negatives = 0, 0, 0, 0
	for i in range(len(y)):
		if y[i] == 0:
			if pred[i] == 0:
				true_negatives += 1
			else:
				false_positives += 1
		else: # if y[i] == 1
			if pred[i] == 1:
				true_positives += 1
			else:
				false_negatives += 1

	true_positive_rate = float(true_positives)/(true_positives + false_negatives)
	false_positive_rate = float(false_positives)/(true_negatives + false_positives)
	true_negative_rate = float(true_negatives)/(true_negatives + false_positives)
	false_negative_rate = float(false_negatives)/(true_positives + false_negatives)
	print "True positives: ", str(true_positives)
	print "True positive rate: ", str(true_positive_rate)
	print "True negatives: ", str(true_negatives)
	print "True negative rate: ", str(true_negative_rate)
	print "False positives: ", str(false_positives)
	print "False positive rate: ", str(false_positive_rate)
	print "False negatives: ", str(false_negatives)
	print "False negative rate: ", str(false_negative_rate)

main()