# botnet-surf
This repo allow us to read in PCap Files and outputs a GUI representing it as a graph/network with various other functions.

## Getting Started

### Prerequisities
```
Python 2.7
```
### Installing
Install pcapfile (necessary to read pcap files):
```
pip install pypcapfile
```
Install PyGObject (necessary to run the GUI, which is built on GTK) for Ubuntu:
```
apt-get install python-gi
```
Install Numpy (necessary for some of the filters implemented in the GUI):
```
apt-get install python-numpy
```
You will next need to install graph-tool, which is a Python wrapper around C++.
Follow https://git.skewed.de/count0/graph-tool/wikis/installation-instructions based on your operating system. Note that installation may be problematic if you run Windows (I followed the instructions for Ubuntu 16.04)

## Authors
Kapil Sinha
