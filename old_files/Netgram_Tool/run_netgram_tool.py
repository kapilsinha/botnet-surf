import sys
import scipy.io
import numpy as np
# This takes in a .mat file given in the Datasets and outputs it without the
# graph representation (keeping just the list of nodes and corresponding
# clusters)
try:
	import NetgramCommunityEvolutionVisualization
except:
	print "Failed to import Netgram Python package. Exiting..."
	sys.exit(1)

a = NetgramCommunityEvolutionVisualization.initialize()
mat_file = sys.argv[1]
a.run_script(mat_file)
# Prevent the program from exiting as soon as the figure is created
raw_input("\nClick enter to exit the program...")
sys.exit(0)
'''
# Prepare .mat file that works
a = scipy.io.loadmat(sys.argv[1])

for i in range(len(a['partition_mergesplit'])):
	#a['partition_mergesplit'][i].reshape(1,)
	#a['partition_mergesplit'][i] = a['partition_mergesplit'][i][1:]
	a['partition_mergesplit'][i][0] = 0
	a['partition_mergesplit'][i][0]

a['data'] = a.pop('partition_mergesplit')
b = {'data': a['data']}
scipy.io.savemat(sys.argv[1].split('.')[0] + '_shortened.mat', a)
scipy.io.savemat(sys.argv[1].split('.')[0] + '_shortened.mat_v2', b)
'''