import sys
import create_graph
from graph_tool.all import *
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
#import numpy as np

# Documentation: https://graph-tool.skewed.de/static/doc/index.html

class Dialog(Gtk.Dialog):

    def __init__(self, message, window=None):
        Gtk.Dialog.__init__(self, "My Dialog", window, 0,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OK, Gtk.ResponseType.OK))

        self.set_default_size(150, 100)

        label = Gtk.Label(message)

        box = self.get_content_area()
        box.add(label)
        self.show_all()

class File_Chooser(Gtk.Box):

    def __init__(self, GUI, window, grid, graph, left, top, width, height):
        Gtk.Box.__init__(self, spacing=6)
        self.GUI = GUI
        self.window = window
        self.grid = grid
        self.old_graph = graph
        self.left = left
        self.top = top
        self.width = width
        self.height = height

        button1 = Gtk.Button("Load PCap File")
        button1.connect("clicked", self.on_file_clicked, "pcap")
        self.add(button1)

        button2 = Gtk.Button("Load Graph File")
        button2.connect("clicked", self.on_file_clicked, "graph")
        self.add(button2)

    def add_filters(self, dialog, name):
        if (name == "pcap"):
            filter_pcap = Gtk.FileFilter()
            filter_pcap.set_name("PCap files")
            filter_pcap.add_mime_type("application/vnd.tcpdump.pcap") # .pcap
            dialog.add_filter(filter_pcap)

        elif (name == "graph"):
            filter_graph = Gtk.FileFilter()
            filter_graph.set_name("Graph files")
            # The commmented out filters do not work
            # filter_graph.add_mime_type("application/octet-stream") # .gt
            # filter_graph.add_mime_type("application/x-dot") # .dot
            filter_graph.add_mime_type("application/xml") # .xml/.graphml
            filter_graph.add_mime_type("application/gml") # .gml
            dialog.add_filter(filter_graph)

        filter_any = Gtk.FileFilter()
        filter_any.set_name("Any files")
        filter_any.add_pattern("*")
        dialog.add_filter(filter_any)

    def on_file_clicked(self, widget, name):
        instruction = "Please choose a %s file" % (name)
        dialog = Gtk.FileChooserDialog("Please choose a file", self.window, \
            Gtk.FileChooserAction.OPEN, (Gtk.STOCK_CANCEL, \
            Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK))

        self.add_filters(dialog, name)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            # NOTE: Maybe remove the print statements later
            print("Open clicked")
            print("File selected: " + dialog.get_filename())
            filename = dialog.get_filename()
            dialog.destroy()
            if (name == "pcap"):
                g = self.handle_pcap_file_upload(filename)

            else: #if (name == "graph"):
                g = self.handle_graph_file_upload(filename)

            self.GUI.restart_window(g)

        elif response == Gtk.ResponseType.CANCEL:
            print("Cancel clicked")
            dialog.destroy()

    def handle_pcap_file_upload(self, filename):
        file_ending = filename.split(".")[-1]
        if file_ending != "pcap":
            dialog = Dialog("File uploaded was not a PCap file.", self.window)
            response = dialog.run()
            dialog.destroy()
            return
        dialog = Dialog("PCap file uploaded. Click OK to generate its graph", \
            self.window)
        # ADD EXTRA OPTION TO SAVE THE GRAPH
        # The button text can be either a stock ID such as gtk.STOCK_OK, 
        # or some arbitrary text. A response ID can be any positive number,
        # or one of the pre-defined GTK Response Type Constants.
        g = Graph()
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            dialog.destroy()
            try:
                g = create_graph.make_graph(filename, save_graph=False)
                graph = GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
                    vertex_fill_color = 'r', pos=sfdp_layout(g), \
                    multilevel=False, display_props=[g.vp.ip_address], update_layout=False)
                graph.set_size_request(self.old_graph.get_size_request()[0], \
                    self.old_graph.get_size_request()[1])
                self.old_graph.destroy()
                self.grid.attach(graph, self.left, self.top, self.width, self.height)
                graph.show()
            except:
                error_dialog = Dialog("Invalid PCap file uploaded.")
                response = error_dialog.run()
                error_dialog.destroy()
        else:
            dialog.destroy()
        return g

    def handle_graph_file_upload(self, filename):
        dialog = Dialog("Graph file uploaded. Click OK to load the graph")
        g = Graph()
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            dialog.destroy()
            try:
                g = load_graph(filename)
                graph = GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
                    vertex_fill_color = 'r', pos=sfdp_layout(g), \
                    multilevel=False, display_props=[g.vp.ip_address], update_layout=False)
                graph.set_size_request(self.old_graph.get_size_request()[0], \
                    self.old_graph.get_size_request()[1])
                self.old_graph.destroy()
                self.grid.attach(graph, self.left, self.top, self.width, self.height)
                graph.show()
            except:
                error_dialog = Dialog("Invalid graph file uploaded.")
                response = error_dialog.run()
                error_dialog.destroy()
        else:
            dialog.destroy()
        return g


class GraphStatisticsDialog(Gtk.Dialog):

    def __init__(self, message, g):
        Gtk.Dialog.__init__(self, message, None, 0,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OK, Gtk.ResponseType.OK))

        self.set_default_size(150, 100)

        label = Gtk.Label(message)

        box = self.get_content_area()
        box.add(label)
        box.add(GraphStatisticsBox(g))

        self.show_all()

class GraphStatisticsBox(Gtk.Box):

    def __init__(self, g):
        Gtk.Box.__init__(self)

        self.liststore = Gtk.ListStore(str, str)
        try:
            self.liststore.append(["Number of nodes", str(g.num_vertices())])
        except:
            self.liststore.append(["Number of nodes", "N/A"])
        try:
            self.liststore.append(["Number of edges", str(g.num_edges())])
        except:
            self.liststore.append(["Number of edges", "N/A"])
        try:
            self.liststore.append(["Time Range (s)", \
                str(g.gp.latest_timestamp - g.gp.earliest_timestamp)])
        except:
            self.liststore.append(["Time Range (s)", "N/A"])
        # Calculating and not saving it is inefficient but this will work for now...
        try:
            v_betweenness = betweenness(g)[0]
            g_central_point_dominance = central_point_dominance(g, v_betweenness)
            self.liststore.append(["Central Point of Dominance", str(g_central_point_dominance)])
        except:
            self.liststore.append(["Central Point of Dominance", "N/A"])
        try:
            g_adjacency_eigenvalue = eigenvector(g)[0]
            self.liststore.append(["Adjacency Eigenvalue", str(g_adjacency_eigenvalue)])
        except:
            self.liststore.append(["Adjacency Eigenvalue", "N/A"])
        try:
            g_cocitation_eigenvalue = hits(g)[0]
            self.liststore.append(["Cocitation Eigenvalue", str(g_cocitation_eigenvalue)])
        except:
            self.liststore.append(["Cocitation Eigenvalue", "N/A"])

        treeview = Gtk.TreeView(model=self.liststore)

        stat_name = Gtk.CellRendererText()
        column_text = Gtk.TreeViewColumn("Statistic", stat_name, text=0)
        treeview.append_column(column_text)

        stat_value = Gtk.CellRendererText()

        column_text = Gtk.TreeViewColumn("Value", stat_value, text=1)
        treeview.append_column(column_text)

        self.add(treeview)

class GraphStatisticsButton(Gtk.Box):

    def __init__(self, g):
        Gtk.Box.__init__(self)
        self.set_border_width(0)
        self.message = "Graph Statistics"
        self.g = g

        button = Gtk.Button.new_with_label(self.message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        dialog = GraphStatisticsDialog(self.message, self.g)
        response = dialog.run()
        dialog.destroy()


class TimeDialog(Gtk.Dialog):

    def __init__(self):
        Gtk.Dialog.__init__(self, "My Dialog", None, 0,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OK, Gtk.ResponseType.OK))

        self.set_default_size(150, 100)

        time_grid = Gtk.Grid()
        self.time_struct = TimeDialogBox()
        time_label_1 = Gtk.Label("Interval Length \n(% of Total)")
        time_label_2 = Gtk.Label("Number of Steps")
        time_grid.attach(self.time_struct, 0, 0, 2, 1)
        time_grid.attach_next_to(time_label_1, self.time_struct, Gtk.PositionType.BOTTOM, 1, 1)
        time_grid.attach_next_to(time_label_2, time_label_1, Gtk.PositionType.RIGHT, 1, 1)

        box = self.get_content_area()
        box.add(time_grid)
        self.show_all()

class TimeDialogBox(Gtk.Box):

    def __init__(self):
        Gtk.Box.__init__(self, spacing=20)
        self.set_border_width(10)

        # (value, lower, upper, step_increment, page_increment, page_size)
        interval_percentage_adjustment = Gtk.Adjustment(5, 1, 100, 1, 10, 0)
        self.interval_spinbutton = Gtk.SpinButton()
        self.interval_spinbutton.set_adjustment(interval_percentage_adjustment)
        self.add(self.interval_spinbutton)

        num_steps_adjustment = Gtk.Adjustment(50, 0, 200, 1, 10, 0)
        self.steps_spinbutton = Gtk.SpinButton()
        self.steps_spinbutton.set_adjustment(num_steps_adjustment)
        self.add(self.steps_spinbutton)

        self.interval_spinbutton.set_numeric(True)
        self.interval_spinbutton.set_update_policy(True)
        self.steps_spinbutton.set_numeric(True)
        self.steps_spinbutton.set_update_policy(True)

    def verify_time_steps(self, interval_length, num_steps):
        if interval_length * (num_steps + 1) >= 100:
            return True
        dialog = Dialog("Invalid interval length and number of steps. "
            "Increase them so that the entire time range can be covered")
        response = dialog.run()
        dialog.destroy()
        return False

    def get_interval_length_and_num_steps(self):
        interval_length = self.interval_spinbutton.get_value_as_int()
        num_steps = self.steps_spinbutton.get_value_as_int()
        if self.verify_time_steps(interval_length, num_steps) == False:
            return (100,0)
        return (interval_length, num_steps)

class TimeSelectButton(Gtk.Box):

    def __init__(self, GUI, g, message):
        Gtk.Box.__init__(self)
        self.set_border_width(10)
        self.GUI = GUI
        self.g = g

        button = Gtk.Button.new_with_label(message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        dialog = TimeDialog()
        response = dialog.run()
        interval_length, num_steps = dialog.time_struct.get_interval_length_and_num_steps()
        if response == Gtk.ResponseType.OK:
            self.GUI.initialize_time_steps(interval_length, num_steps)
            dialog.destroy()

class TimeStepButton(Gtk.Box):
    def __init__(self, GUI, message):
        Gtk.Box.__init__(self)
        self.set_border_width(10)
        self.GUI = GUI

        button = Gtk.Button.new_with_label(message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        self.GUI.do_time_step()

class TimeRangeLabel(Gtk.Box):

    def __init__(self, GUI, time_start, time_end, latest_timestamp):
        Gtk.Box.__init__(self, spacing=6)
        self.GUI = GUI
        self.time_start = time_start
        self.time_end = time_end
        self.latest_timestamp = latest_timestamp

        label = Gtk.Label("Time Range: " + \
            str(100 * float(self.time_start)/self.latest_timestamp) \
            + "% - " + str(100 * float(self.time_end)/self.latest_timestamp) + "%")
        self.add(label)


class VertexFilterBox(Gtk.Box):

    def __init__(self, GUI, g):
        Gtk.Box.__init__(self)

        self.GUI = GUI
        self.g = g

        self.liststore = Gtk.ListStore(str, int, int)
        self.liststore.append(["Out-degree", 0, 100])
        self.liststore.append(["In-degree", 0, 100])
        self.liststore.append(["# of neighbors", 0, 100])
        self.liststore.append(["Page Rank", 0, 100])
        self.liststore.append(["Betweenness", 0, 100])
        self.liststore.append(["Closeness", 0, 100])
        self.liststore.append(["Eigenvector", 0, 100])
        self.liststore.append(["Authority centrality", 0, 100])
        self.liststore.append(["Hub centrality", 0, 100])

        treeview = Gtk.TreeView(model=self.liststore)

        filter_name = Gtk.CellRendererText()
        column_text = Gtk.TreeViewColumn("Vertex Filters", filter_name, text=0)
        treeview.append_column(column_text)

        self.filter_low = Gtk.CellRendererSpin()
        self.filter_low.connect("edited", self.low_on_amount_edited)
        self.filter_low.set_property("editable", True)

        self.filter_high = Gtk.CellRendererSpin()
        self.filter_high.connect("edited", self.high_on_amount_edited)
        self.filter_high.set_property("editable", True)

        low_adjustment = Gtk.Adjustment(0, 0, 99, 1, 10, 0)
        self.filter_low.set_property("adjustment", low_adjustment)

        high_adjustment = Gtk.Adjustment(100, 1, 100, 1, 10, 0)
        self.filter_high.set_property("adjustment", high_adjustment)

        low_spin = Gtk.TreeViewColumn("Lower bound (%)", self.filter_low, text=1)
        high_spin = Gtk.TreeViewColumn("Upper bound (%)", self.filter_high, text=2)
        treeview.append_column(low_spin)
        treeview.append_column(high_spin)

        self.add(treeview)

    def low_on_amount_edited(self, widget, path, value):
        value = int(value)
        if (value >= self.filter_high.get_property("adjustment").get_value()):
            return
        self.liststore[path][1] = value
        # REPLACE with switch statement later
        '''
        if self.liststore[path][0] == "Out-degree":
            #u = GraphView(self.g, vfilt=lambda v: v.out_degree() > \
            #   max(self.g.get_out_degrees(self.g.get_vertices())) * float(value/100))
            #self.g.set_vertex_filter(None)
            #new_g = self.g
            out_degree = self.g.new_vertex_property("bool")
            print self.g.get_vertices()
            out_degree.a = np.random.randint(0, 2, self.g.num_vertices())
            # the above statement fails on the second time I change this thing
            #f = lambda a: a > \
            #    max(self.g.get_out_degrees(self.g.get_vertices())) * float(value/100)
            #out_degree.a = f(self.g.get_out_degrees(self.g.get_vertices()))
            #print f(self.g.get_out_degrees(self.g.get_vertices()))
            #self.g.set_vertex_filter(out_degree)
            self.g.set_vertex_filter(out_degree)
            print self.g.num_vertices()
            self.GUI.apply_filter(self.g)
        else:
            self.g.set_vertex_filter(None)
            self.GUI.apply_filter(self.g)
        '''


    def high_on_amount_edited(self, widget, path, value):
        if (int(value) <= self.filter_low.get_property("adjustment").get_value()):
            return
        self.liststore[path][2] = int(value)

class EdgeFilterBox(Gtk.Box):

    def __init__(self, GUI, g):
        Gtk.Box.__init__(self)

        self.GUI = GUI
        self.g = g

        self.liststore = Gtk.ListStore(str, int, int)
        self.liststore.append(["# of bytes", 0, 100])
        self.liststore.append(["Betweenness", 0, 100])

        treeview = Gtk.TreeView(model=self.liststore)

        filter_name = Gtk.CellRendererText()
        column_text = Gtk.TreeViewColumn("Edge Filters", filter_name, text=0)
        treeview.append_column(column_text)

        self.filter_low = Gtk.CellRendererSpin()
        self.filter_low.connect("edited", self.low_on_amount_edited)
        self.filter_low.set_property("editable", True)

        self.filter_high = Gtk.CellRendererSpin()
        self.filter_high.connect("edited", self.high_on_amount_edited)
        self.filter_high.set_property("editable", True)

        low_adjustment = Gtk.Adjustment(0, 0, 99, 1, 10, 0)
        self.filter_low.set_property("adjustment", low_adjustment)

        high_adjustment = Gtk.Adjustment(100, 1, 100, 1, 10, 0)
        self.filter_high.set_property("adjustment", high_adjustment)

        low_spin = Gtk.TreeViewColumn("Lower bound (%)", self.filter_low, text=1)
        high_spin = Gtk.TreeViewColumn("Upper bound (%)", self.filter_high, text=2)
        treeview.append_column(low_spin)
        treeview.append_column(high_spin)

        self.add(treeview)

    def low_on_amount_edited(self, widget, path, value):
        if (int(value) >= self.filter_high.get_property("adjustment").get_value()):
            return
        self.liststore[path][1] = int(value)

    def high_on_amount_edited(self, widget, path, value):
        if (int(value) <= self.filter_low.get_property("adjustment").get_value()):
            return
        self.liststore[path][2] = int(value)


class GUI:

    def __init__(self):

        self.win = Gtk.Window()
        self.window_grid = Gtk.Grid()

        self.time_start = 0 # start of current time interval
        self.time_end = 100 # end of current time interval
        self.interval_length = 100
        self.num_steps = 0
        self.step_time = 0

        self.g = Graph()
        self.graph = GraphWidget(self.g, pos=sfdp_layout(self.g))
        self.graph_left, self.graph_top, self.graph_width, self.graph_height \
            = 0, 10, 10, 10

        self.file_box = Gtk.Box(spacing=10)
        self.set_time_button = TimeSelectButton(self, self.g, \
            "Select time steps and intervals")
        self.time_step_button = TimeStepButton(self, "Step")
        self.time_range_label = Gtk.Label("0.0% - 100.0%")

        self.graph_stats_button = GraphStatisticsButton(self.g)
        self.vertex_filter_box = Gtk.Box(spacing=10)
        self.edge_filter_box = Gtk.Box(spacing=10)

        self.win.connect("delete-event", Gtk.main_quit)

        self.start_window()

    def start_window(self):
        self.graph.set_size_request(700, 700)

        self.file_box.pack_start(Gtk.Label("Upload a file"), True, True, 0)
        self.file_box.pack_start(File_Chooser(self, self.win, self.window_grid, self.graph, \
            self.graph_left, self.graph_top, self.graph_width, self.graph_height), True, True, 0)
        
        self.vertex_filter_box.pack_start(VertexFilterBox(self, self.g), True, True, 0)
        self.edge_filter_box.pack_start(EdgeFilterBox(self, self.g), True, True, 0)
        
        self.window_grid.attach(self.file_box, 0, 0, 3, 1)
        self.window_grid.attach(self.set_time_button, 0, 1, 2, 1)
        self.window_grid.attach(self.graph_stats_button, 0, 2, 1, 1)
        self.window_grid.attach(self.time_step_button, 0, 3, 1, 1)
        self.window_grid.attach(self.time_range_label, 0, 4, 1, 1)

        self.window_grid.attach(self.vertex_filter_box, 3, 0, 3, 10)
        self.window_grid.attach(self.edge_filter_box, 6, 0, 3, 10)
        self.window_grid.attach(self.graph, self.graph_left, \
            self.graph_top, self.graph_width, self.graph_height)

        self.win.add(self.window_grid)

        self.win.show_all()

    def restart_window(self, g = Graph()):
        
        self.window_grid.destroy()
        
        self.window_grid = Gtk.Grid()
        
        self.g = g
        self.graph = GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
                    vertex_fill_color = 'r', pos=sfdp_layout(g), \
                    multilevel=False, display_props=[self.g.vp.ip_address], \
                    update_layout=False)
        
        self.file_box = Gtk.Box(spacing=10)
        self.set_time_button = TimeSelectButton(self, g, \
            "Select time steps and intervals")
        self.time_step_button = TimeStepButton(self, "Step")
        self.time_range_label = Gtk.Label("0.0% - 100.0%")

        self.graph_stats_button = GraphStatisticsButton(self.g)
        self.vertex_filter_box = Gtk.Box(spacing=10)
        self.edge_filter_box = Gtk.Box(spacing=10)
        
        self.start_window()

    def apply_filter(self, g):
        #self.graph.destroy()
        self.g = g
        self.graph = GraphWidget(self.g, edge_pen_width = 1.2, vertex_size=10, \
                    vertex_fill_color = 'r', pos=sfdp_layout(g), \
                    multilevel=False, display_props=[self.g.vp.ip_address], update_layout=False)
                    #multilevel=False, display_props=None, update_layout=False)
        self.window_grid.attach(self.graph, self.graph_left, \
            self.graph_top, self.graph_width, self.graph_height)
        self.win.show_all()

    def initialize_time_steps(self, interval_length, num_steps):
        self.interval_length = interval_length
        self.num_steps = num_steps
        try:
            self.step_time = float(self.g.gp.latest_timestamp \
                - self.g.gp.earliest_timestamp - self.interval_length) \
                / self.num_steps
        except:
            self.step_time = 0

        self.g.set_edge_filter(None)

        self.time_start = self.g.gp.earliest_timestamp
        self.time_end = self.g.gp.earliest_timestamp + (self.g.gp.latest_timestamp \
            - self.g.gp.earliest_timestamp) * float(interval_length)/100
        self.update_time_range()

    def update_time_range(self):

        time_start_percent = 100 * float(self.time_start \
            - self.g.gp.earliest_timestamp) / (self.g.gp.latest_timestamp \
            - self.g.gp.earliest_timestamp)
        time_end_percent = 100 * float(self.time_end - \
            self.g.gp.earliest_timestamp) / (self.g.gp.latest_timestamp \
            - self.g.gp.earliest_timestamp)
        self.time_range_label.set_label("Time Range: %.1f%% - %.1f%%" \
            % (time_start_percent, time_end_percent))

        time_filter = self.g.new_edge_property("bool")
        for e in self.g.edges():
            edge_timestamp = self.g.ep.initial_timestamp[e]
            if edge_timestamp > self.time_start \
                and edge_timestamp < self.time_end:
                time_filter[e] = True
            else:
                time_filter[e] = False

        self.g.set_edge_filter(time_filter)
        self.apply_filter(self.g)

    def do_time_step(self):
        self.g.set_edge_filter(None)
        if self.time_end + self.step_time  > self.g.gp.latest_timestamp:
            self.time_start = self.g.gp.latest_timestamp - self.step_time
            self.time_end = self.g.gp.latest_timestamp
        else:   
            self.time_start += self.step_time
            self.time_end += self.step_time
        self.update_time_range()


def main():
    app = GUI()
    Gtk.main()

if __name__ == "__main__":
    sys.exit(main())

'''
# Add ALL possible graph statistics to the lists
# Centrality measures: https://graph-tool.skewed.de/static/doc/centrality.html
v_page_rank = pagerank(g)
v_betweenness, e_betweenness = betweenness(g)
v_closeness = closeness(g)
g_central_point_dominance = central_point_dominance(g, v_betweenness)
g_adjacency_eigenvalue, v_eigenvector = eigenvector(g)
v_katz = katz(g)
g_cocitation_eigenvalue, v_authority_centrality, v_hub_centrality = hits(g)
v_eigentrust = eigentrust(g)
# not including trust transitivity since we have no trust values
'''
# Graph topology measures: https://graph-tool.skewed.de/static/doc/flow.html

# Misc. statistics: https://graph-tool.skewed.de/static/doc/stats.html
# If there's time, look into making averages & histograms of properties of edges and vertices

# Inferring network structure: https://graph-tool.skewed.de/static/doc/demos/inference/inference.html
# Can generate images and interactive windows of the groupings etc...requires deeper reading

