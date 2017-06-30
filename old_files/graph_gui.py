import sys
import create_graph
from graph_tool.all import *
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
import numpy as np

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

    def __init__(self, GUI, g, message):
        Gtk.Dialog.__init__(self, message, None, 0,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_OK, Gtk.ResponseType.OK))

        self.set_default_size(150, 100)

        label = Gtk.Label(message)

        box = self.get_content_area()
        box.add(label)
        box.add(GraphStatisticsBox(g, GUI))

        self.show_all()

class GraphStatisticsBox(Gtk.Box):

    def __init__(self, g, GUI):
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
                "%d" %(GUI.time_end - GUI.time_start)])
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

    def __init__(self, GUI, g):
        Gtk.Box.__init__(self)
        self.set_border_width(0)
        self.message = "Graph Statistics"
        self.GUI = GUI
        self.g = g

        button = Gtk.Button.new_with_label(self.message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        dialog = GraphStatisticsDialog(self.GUI, self.g, self.message)
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
        time_label_1 = Gtk.Label("Interval Length (s)")
        time_label_2 = Gtk.Label("Step Length (s)")
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
        interval_adjustment = Gtk.Adjustment(300, 10, 1500, 25, 100, 0)
        self.interval_spinbutton = Gtk.SpinButton()
        self.interval_spinbutton.set_adjustment(interval_adjustment)
        self.add(self.interval_spinbutton)

        step_length_adjustment = Gtk.Adjustment(150, 5, 1000, 25, 100, 0)
        self.steps_spinbutton = Gtk.SpinButton()
        self.steps_spinbutton.set_adjustment(step_length_adjustment)
        self.add(self.steps_spinbutton)

        self.interval_spinbutton.set_numeric(True)
        self.interval_spinbutton.set_update_policy(True)
        self.steps_spinbutton.set_numeric(True)
        self.steps_spinbutton.set_update_policy(True)

    def verify_time_steps(self, interval_length, step_length):
        if interval_length >= step_length:
            return True
        dialog = Dialog("Your interval length must be more than your step length" \
            " to cover the entire time range")
        response = dialog.run()
        dialog.destroy()
        return False

    def get_interval_step_length(self):
        interval_length = self.interval_spinbutton.get_value_as_int()
        step_length = self.steps_spinbutton.get_value_as_int()
        if self.verify_time_steps(interval_length, step_length) == False:
            return (300,150)
        return (interval_length, step_length)

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
        interval_length, step_length = dialog.time_struct.get_interval_step_length()
        if response == Gtk.ResponseType.OK:
            self.GUI.initialize_time_steps(interval_length, step_length)
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
        self.filters = ["Out-degree", "In-degree", "# of neighbors", \
            "Page Rank", "Betweenness", "Closeness", "Eigenvector", \
            "Authority centrality", "Hub centrality"]
        # can also have in-neighbors or out-neighbors
        for filter_name in self.filters:
            self.liststore.append([filter_name, 0, 100])

            self.GUI.vertex_filters[filter_name + "_low"] = \
                self.g.new_vertex_property("bool")
            self.GUI.vertex_filters[filter_name + "_low"].a = \
                np.array([True] * g.num_vertices())
            self.GUI.vertex_filters[filter_name + "_high"] = \
                self.g.new_vertex_property("bool")
            self.GUI.vertex_filters[filter_name + "_high"].a = \
                np.array([True] * g.num_vertices())

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

    # I'm sure a lot of this code is repetitive and can be cleaned up. Some of
    # it may also be somewhat inefficient, but again, it works (except for the
    # occasional segmentation fault, which happens when I think I apply filters
    # in rapid succession and perhaps overload the program)
    def low_on_amount_edited(self, widget, path, value):
        value = int(value)
        if (value >= self.filter_high.get_property("adjustment").get_value()):
            return
        name = self.liststore[path][0]
        self.liststore[path][1] = value

        self.g.set_vertex_filter(None)

        if name == "Out-degree":
            for v in self.g.vertices():
                max_out_degree = max(self.g.get_out_degrees(range(self.g.num_vertices())))
                self.GUI.vertex_filters[name + "_low"][v] = (v.out_degree() \
                    >= max(self.g.get_out_degrees(range(self.g.num_vertices()))) \
                    * float(value)/100)
        elif name == "In-degree":
            for v in self.g.vertices():
                max_in_degree = max(self.g.get_in_degrees(range(self.g.num_vertices())))
                self.GUI.vertex_filters[name + "_low"][v] = (v.in_degree() \
                    >= max(self.g.get_in_degrees(range(self.g.num_vertices()))) \
                    * float(value)/100)
        elif name == "# of neighbors":
            max_neighbors = 0
            # not efficient but it works
            for v in self.g.vertices():
                max_neighbors = max(max_neighbors, len(self.g.get_in_neighbours(int(v))) \
                    + len(self.g.get_out_neighbours(int(v))))
            for v in self.g.vertices():
                num_neighbors = len(self.g.get_in_neighbours(int(v))) + \
                    len(self.g.get_out_neighbours(int(v)))
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (num_neighbors >= max_neighbors * float(value)/100)

        elif name == "Page Rank":
            pr = pagerank(self.g)
            max_pagerank = max(pr.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (pr[v] >= max_pagerank * float(value)/100)

        elif name == "Betweenness":
            vp = betweenness(self.g)[0]
            max_betweenness = max(vp.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (vp[v] >= max_betweenness * float(value)/100)

        elif name == "Closeness":
            c = closeness(self.g)
            max_closeness = max(c.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (c[v] >= max_closeness * float(value)/100)

        elif name == "Eigenvector":
            x = eigenvector(self.g)[1]
            max_eigenvector = max(x.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (x[v] >= max_eigenvector * float(value)/100)

        elif name == "Authority centrality":
            auth = hits(self.g)[1]
            max_authority = max(auth.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (auth[v] >= max_authority * float(value)/100)

        elif name == "Hub centrality":
            hub = hits(self.g)[2]
            max_hub = max(hub.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_low"][v] \
                    = (hub[v] >= max_hub * float(value)/100)

        self.GUI.set_overall_filter()

    # Almost exactly the same as the above function except switching >= to <=
    # and replacing "_low" with "_high"
    def high_on_amount_edited(self, widget, path, value):
        value = int(value)
        if (value <= self.filter_low.get_property("adjustment").get_value()):
            return
        name = self.liststore[path][0]
        self.liststore[path][2] = value

        self.g.set_vertex_filter(None)

        if name == "Out-degree":
            for v in self.g.vertices():
                max_out_degree = max(self.g.get_out_degrees(range(self.g.num_vertices())))
                self.GUI.vertex_filters[name + "_high"][v] = (v.out_degree() \
                    <= max(self.g.get_out_degrees(range(self.g.num_vertices()))) \
                    * float(value)/100)
        elif name == "In-degree":
            for v in self.g.vertices():
                max_in_degree = max(self.g.get_in_degrees(range(self.g.num_vertices())))
                self.GUI.vertex_filters[name + "_high"][v] = (v.in_degree() \
                    <= max(self.g.get_in_degrees(range(self.g.num_vertices()))) \
                    * float(value)/100)
        elif name == "# of neighbors":
            max_neighbors = 0
            # not efficient but it works
            for v in self.g.vertices():
                max_neighbors = max(max_neighbors, len(self.g.get_in_neighbours(int(v))) \
                    + len(self.g.get_out_neighbours(int(v))))
            for v in self.g.vertices():
                num_neighbors = len(self.g.get_in_neighbours(int(v))) + \
                    len(self.g.get_out_neighbours(int(v)))
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (num_neighbors <= max_neighbors * float(value)/100)

        elif name == "Page Rank":
            pr = pagerank(self.g)
            max_pagerank = max(pr.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (pr[v] <= max_pagerank * float(value)/100)

        elif name == "Betweenness":
            vp = betweenness(self.g)[0]
            max_betweenness = max(vp.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (vp[v] <= max_betweenness * float(value)/100)

        elif name == "Closeness":
            c = closeness(self.g)
            max_closeness = max(c.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (c[v] <= max_closeness * float(value)/100)

        elif name == "Eigenvector":
            x = eigenvector(self.g)[1]
            max_eigenvector = max(x.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (x[v] <= max_eigenvector * float(value)/100)

        elif name == "Authority centrality":
            auth = hits(self.g)[1]
            max_authority = max(auth.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (auth[v] <= max_authority * float(value)/100)

        elif name == "Hub centrality":
            hub = hits(self.g)[2]
            max_hub = max(hub.get_array())
            for v in self.g.vertices():
                self.GUI.vertex_filters[name + "_high"][v] \
                    = (hub[v] <= max_hub * float(value)/100)

        self.GUI.set_overall_filter()

    # Resets filter low and high percentages to 0 and 100, respectively
    def reset_filters(self):
        for i in range(len(self.filters)):
            self.liststore.set_value(self.liststore.get_iter(i), 1, 0)
            self.liststore.set_value(self.liststore.get_iter(i), 2, 100)

class EdgeFilterBox(Gtk.Box):

    def __init__(self, GUI, g):
        Gtk.Box.__init__(self)

        self.GUI = GUI
        self.g = g

        self.liststore = Gtk.ListStore(str, int, int)
        self.filters = ["# of bytes", "Betweenness"]
        for filter_name in self.filters:
            self.liststore.append([filter_name, 0, 100])
            self.GUI.edge_filters[filter_name + "_low"] = \
                self.g.new_edge_property("bool")
            self.GUI.edge_filters[filter_name + "_low"].a = \
                np.array([True] * g.num_edges())
            self.GUI.edge_filters[filter_name + "_high"] = \
                self.g.new_edge_property("bool")
            self.GUI.edge_filters[filter_name + "_high"].a = \
                np.array([True] * g.num_edges())

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
        value = int(value)
        if (value >= self.filter_high.get_property("adjustment").get_value()):
            return
        name = self.liststore[path][0]
        self.liststore[path][1] = value

        self.g.set_edge_filter(None)

        if name == "# of bytes":
            max_number_bytes = max(self.g.ep.num_bytes.get_array())
            for e in self.g.edges():
                self.GUI.edge_filters[name + "_low"][e] \
                    = (self.g.ep.num_bytes[e] >= max_number_bytes * float(value)/100)
        elif name == "Betweenness":
            ep = betweenness(self.g)[1]
            max_betweenness = max(ep.get_array())
            for e in self.g.edges():
                self.GUI.edge_filters[name + "_low"][e] \
                    = (ep[e] >= max_betweenness * float(value)/100)

        self.GUI.set_overall_filter()

    def high_on_amount_edited(self, widget, path, value):
        value = int(value)
        if (value <= self.filter_low.get_property("adjustment").get_value()):
            return
        name = self.liststore[path][0]
        self.liststore[path][2] = value

        self.g.set_edge_filter(None)

        if name == "# of bytes":
            max_number_bytes = max(self.g.ep.num_bytes.get_array())
            for e in self.g.edges():
                self.GUI.edge_filters[name + "_high"][e] \
                    = (self.g.ep.num_bytes[e] <= max_number_bytes * float(value)/100)
        elif name == "Betweenness":
            ep = betweenness(self.g)[1]
            max_betweenness = max(ep.get_array())
            for e in self.g.edges():
                self.GUI.edge_filters[name + "_high"][e] \
                    = (ep[e] <= max_betweenness * float(value)/100)
        
        self.GUI.set_overall_filter()

    def reset_filters(self):
        for i in range(len(self.filters)):
            self.liststore.set_value(self.liststore.get_iter(i), 1, 0)
            self.liststore.set_value(self.liststore.get_iter(i), 2, 100)

class ResetFilters(Gtk.Box):

    def __init__(self, GUI, g, message, name, filter_box):
        Gtk.Box.__init__(self)
        self.set_border_width(10)
        self.GUI = GUI
        self.g = g
        self.name = name
        self.filter_box = filter_box

        button = Gtk.Button.new_with_label(message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        self.filter_box.reset_filters()
        if self.name == "vertex":
            self.GUI.reset_vertex_filters()
        else: # self.name == "edge"
            self.GUI.reset_edge_filters()


class GUI:

    def __init__(self):

        self.win = Gtk.Window()
        self.window_grid = Gtk.Grid()

        self.time_start = 0 # start of current time interval
        self.time_end = 0 # end of current time interval
        self.interval_length = 300
        self.step_length = 150

        # Dictionaries of property maps (vertex or edge) to filter the graph
        self.vertex_filters = {}
        self.edge_filters = {}

        self.g = Graph()
        self.graph = GraphWidget(self.g, pos=sfdp_layout(self.g))
        self.graph_left, self.graph_top, self.graph_width, self.graph_height \
            = 0, 10, 10, 10

        self.file_box = Gtk.Box(spacing=10)
        self.set_time_button = TimeSelectButton(self, self.g, \
            "Select time steps and intervals")
        self.time_step_button = TimeStepButton(self, "Step")
        self.time_range_label = Gtk.Label("")

        self.graph_stats_button = GraphStatisticsButton(self, self.g)

        self.vertex_filter_box = VertexFilterBox(self, self.g)
        self.edge_filter_box = EdgeFilterBox(self, self.g)

        self.vertex_filter_reset = ResetFilters(self, self.g, \
            "Reset vertex filters", "vertex", self.vertex_filter_box)
        self.edge_filter_reset = ResetFilters(self, self.g, \
            "Reset edge filters", "edge", self.edge_filter_box)

        self.win.connect("delete-event", Gtk.main_quit)

        self.start_window()

    def start_window(self):
        self.graph.set_size_request(700, 700)

        self.file_box.pack_start(Gtk.Label("Upload a file"), True, True, 0)
        self.file_box.pack_start(File_Chooser(self, self.win, self.window_grid, self.graph, \
            self.graph_left, self.graph_top, self.graph_width, self.graph_height), True, True, 0)
          
        self.window_grid.attach(self.file_box, 0, 0, 3, 1)
        self.window_grid.attach(self.set_time_button, 0, 1, 2, 1)
        self.window_grid.attach(self.graph_stats_button, 0, 2, 1, 1)
        self.window_grid.attach(self.time_step_button, 0, 3, 1, 1)
        self.window_grid.attach(self.time_range_label, 0, 4, 1, 1)

        self.window_grid.attach(self.vertex_filter_box, 3, 0, 3, 8)
        self.window_grid.attach(self.edge_filter_box, 6, 0, 3, 3)
        self.window_grid.attach(self.vertex_filter_reset, 6, 3, 1, 1)
        self.window_grid.attach(self.edge_filter_reset, 6, 4, 1, 1)

        self.window_grid.attach(self.graph, self.graph_left, \
            self.graph_top, self.graph_width, self.graph_height)

        self.win.add(self.window_grid)

        self.win.show_all()

    def restart_window(self, g = Graph()):
        
        self.window_grid.destroy()
        
        self.window_grid = Gtk.Grid()
        
        self.g = g
        self.time_start = self.g.gp.earliest_timestamp
        self.time_end = self.g.gp.latest_timestamp
        try:
            self.graph = GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
                vertex_fill_color = 'r', pos=sfdp_layout(g), \
                multilevel=False, display_props=[self.g.vp.ip_address], \
                update_layout=False)
        except:
            self.graph = GraphWidget(g, edge_pen_width = 1.2, vertex_size=10, \
                vertex_fill_color = 'r', pos=sfdp_layout(g), \
                multilevel=False, display_props=None, update_layout=False)
        
        self.file_box = Gtk.Box(spacing=10)
        self.set_time_button = TimeSelectButton(self, g, \
            "Select time steps and intervals")
        self.time_step_button = TimeStepButton(self, "Step")
        self.time_range_label = Gtk.Label("")

        self.graph_stats_button = GraphStatisticsButton(self, self.g)
        self.vertex_filter_box = VertexFilterBox(self, self.g)
        self.edge_filter_box = EdgeFilterBox(self, self.g)
        self.vertex_filter_reset = ResetFilters(self, self.g, \
            "Reset vertex filters", "vertex", self.vertex_filter_box)
        self.edge_filter_reset = ResetFilters(self, self.g, \
            "Reset edge filters", "edge", self.edge_filter_box)
        
        self.start_window()

    def apply_filter(self, g):
        #self.graph.destroy()
        self.g = g
        try:
            self.graph = GraphWidget(self.g, edge_pen_width = 1.2, vertex_size=10, \
                vertex_fill_color = 'r', pos=sfdp_layout(g), \
                multilevel=False, display_props=[self.g.vp.ip_address], \
                update_layout=False)
        except:
            self.graph = GraphWidget(self.g, edge_pen_width = 1.2, vertex_size=10, \
                vertex_fill_color = 'r', pos=sfdp_layout(g), \
                multilevel=False, display_props=None, update_layout=False)
        self.window_grid.attach(self.graph, self.graph_left, \
            self.graph_top, self.graph_width, self.graph_height)
        self.win.show_all()

    def initialize_time_steps(self, interval_length, step_length):
        self.interval_length = interval_length
        self.step_length = step_length

        self.g.set_edge_filter(None)

        self.time_start = self.g.gp.earliest_timestamp
        self.time_end = min(self.g.gp.earliest_timestamp + self.interval_length, \
            self.g.gp.latest_timestamp)
        self.update_time_range()

    def update_time_range(self):

        self.time_range_label.set_label("Time Range: %d s - %d s" \
            % (self.time_start - self.g.gp.earliest_timestamp, \
               self.time_end - self.g.gp.earliest_timestamp))

        time_filter = self.g.new_edge_property("bool")
        for e in self.g.edges():
            edge_timestamp = self.g.ep.initial_timestamp[e]
            if edge_timestamp > self.time_start \
                and edge_timestamp < self.time_end:
                time_filter[e] = True
            else:
                time_filter[e] = False

        self.edge_filters['time_filter'] = time_filter
        self.set_overall_filter()

    def do_time_step(self):
        self.g.set_edge_filter(None)
        if self.time_end + self.step_length > self.g.gp.latest_timestamp:
            self.time_start = self.g.gp.latest_timestamp - self.step_length
            self.time_end = self.g.gp.latest_timestamp
        else:   
            self.time_start += self.step_length
            self.time_end += self.step_length
        self.update_time_range()

    def set_overall_filter(self):
        self.g.set_vertex_filter(None)
        self.g.set_edge_filter(None)
        overall_vertex_filter = self.g.new_vertex_property("bool")
        overall_vertex_filter.a = np.array([True] * self.g.num_vertices())

        overall_edge_filter = self.g.new_edge_property("bool")
        overall_edge_filter.a = np.array([True] * self.g.num_edges())

        for vertex_filter in self.vertex_filters.values():
            overall_vertex_filter.a = overall_vertex_filter.get_array() \
                & vertex_filter.get_array()

        for edge_filter in self.edge_filters.values():
            overall_edge_filter.a = overall_edge_filter.get_array() \
                & edge_filter.get_array()

        self.g.set_vertex_filter(overall_vertex_filter)
        self.g.set_edge_filter(overall_edge_filter)
        self.apply_filter(self.g)

    def reset_vertex_filters(self):
        self.g.set_vertex_filter(None)
        self.g.set_edge_filter(None)
        for name in self.vertex_filters.keys():
            self.vertex_filters[name].a = np.array([True] * self.g.num_vertices())
        self.set_overall_filter()
        
    def reset_edge_filters(self):
        self.g.set_vertex_filter(None)
        self.g.set_edge_filter(None)
        for name in self.edge_filters.keys():
            if name != 'time_filter':
                self.edge_filters[name].a = np.array([True] * self.g.num_edges())
        self.set_overall_filter()


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

