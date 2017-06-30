import sys
import create_graph
from graph_tool.all import *
import bisect
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, Gtk
# Documentation: https://graph-tool.skewed.de/static/doc/index.html

'''
Displays graph in the type you select:
type - "graph_draw", "interactive_window", "GraphWidget", "GraphWindow"
Animations - https://graph-tool.skewed.de/static/doc/demos/animation/animation.html
'''
def display_graph(g, type, edge_pen_width = 1.2, vertex_size = 10, \
	edge_color = 'k', vertex_fill_color = 'r', pos = None, \
	output_size = (1000, 1000), output = "graph.pdf", update_layout = False, \
	geometry = (800, 800)):
	# can't figure out how to put vprops and eprops
	if pos == None:
		pos = sfdp_layout(g)
	if type == "graph_draw":
		graph_draw(g, edge_pen_width = 1.2, vertex_size = 10, \
			edge_color = 'k', vertex_fill_color='r', pos=sfdp_layout(g), \
			output_size=(800, 800), output="graph.pdf")
	elif type == "interactive_window":
		interactive_window(g, edge_pen_width = edge_pen_width, \
			vertex_size = vertex_size, edge_color = edge_color, \
			vertex_fill_color = vertex_fill_color, pos=pos, \
			update_layout=update_layout, geometry=geometry)
	else:
		print "Invalid type"

try:
	FILENAME = sys.argv[1]
except:
	print("The command-line argument should be the name of the pcap file")
	sys.exit(1)

g = create_graph.make_graph(FILENAME, save_graph=True)
#g = load_graph("graph_structure.gt")

# display_graph(g, "interactive_window")
# You can filter some parts out
# bv, be = betweenness(g)
# u = GraphView(g, efilt=lambda e: be[e] > be.a.max() / 2)

pos = sfdp_layout(g) # layout positions
ecolor = g.new_edge_property("vector<double>")
for e in g.edges():
    ecolor[e] = [0.6, 0.6, 0.6, 1]
vcolor = g.new_vertex_property("vector<double>")
for v in g.vertices():
    vcolor[v] = [0.6, 0.6, 0.6, 1]

win = GraphWindow(g, edge_pen_width = 1.2, vertex_size=10, \
	vertex_fill_color = 'r', pos=sfdp_layout(g), multilevel=False, \
	display_props=None, update_layout=False, geometry=(800,800))

orange = [0.807843137254902, 0.3607843137254902, 0.0, 1.0]
old_src = None
count = 0
def update_bfs(widget, event, save_pics=False):
    global old_src, g, count, win
    src = widget.picked
    if src is None:
        return True
    if isinstance(src, PropertyMap):
        src = [v for v in g.vertices() if src[v]]
        if len(src) == 0:
            return True
        src = src[0]
    if src == old_src:
        return True
    old_src = src
    pred = shortest_distance(g, src, max_dist=3, pred_map=True)[1]
    for e in g.edges():
        ecolor[e] = [0.6, 0.6, 0.6, 1]
    for v in g.vertices():
        vcolor[v] = [0.6, 0.6, 0.6, 1]
    for v in g.vertices():
        w = g.vertex(pred[v])
        if w < g.num_vertices():
            e = g.edge(w, v)
            if e is not None:
                ecolor[e] = orange
                vcolor[v] = vcolor[w] = orange
    widget.regenerate_surface()
    widget.queue_draw()

    if save_pics:
        window = widget.get_window()
        pixbuf = Gdk.pixbuf_get_from_window(window, 0, 0, 500, 400)
        pixbuf.savev(r'bfs%06d.png' % count, 'png', [], [])
        count += 1

# Bind the function above as a motion notify handler
# Events - https://graph-tool.skewed.de/static/doc/draw.html#graph_tool.draw.GraphWindow
#win.graph.connect("motion_notify_event", update_bfs)

# We will give the user the ability to stop the program by closing the window.
win.connect("delete_event", Gtk.main_quit)

# Actually show the window, and start the main loop.
win.show_all()
Gtk.main()

"""
GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
	vertex_fill_color = 'r', pos=sfdp_layout(g), \
	multilevel=False, display_props=None, \
	update_layout=False, geometry=(1000,1000))

"""