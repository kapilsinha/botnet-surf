# botnet-surf
This repo allow us to read in PCap Files and outputs a GUI with various other functions.

## Getting Started

### Prerequisities
```
Python 2.7
```
### Installing
The following will download pcapfile (necessary to read pcap files) and PyGObject (necessary to run the GUI, which runs using GTK)
```
pip install pypcapfile
apt-get install python-gi
```
You will next need to install graph-tool, which is a Python wrapper around C++.
Follow https://git.skewed.de/count0/graph-tool/wikis/installation-instructions based on your operating system. Note that installation may be problematic if you rub Windows (I followed the instructions for Ubuntu 16.04)

## Authors
Kapil Sinha
