import sys
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

# Documentation: https://graph-tool.skewed.de/static/doc/index.html

class SpecialBox(Gtk.Box):

    def __init__(self, GUI):
        Gtk.Box.__init__(self)

        self.GUI = GUI

        self.liststore = Gtk.ListStore(str, int, int)
        self.liststore.append(["Apple", 0, 100])
        self.liststore.append(["Pear", 0, 100])
        self.liststore.append(["Orange", 0, 100])

        treeview = Gtk.TreeView(model=self.liststore)

        filter_name = Gtk.CellRendererText()
        column_text = Gtk.TreeViewColumn("Fruit is good", filter_name, text=0)
        treeview.append_column(column_text)

        self.filter_low = Gtk.CellRendererSpin()
        self.filter_low.connect("edited", self.low_on_amount_edited)
        self.filter_low.set_property("editable", True)

        low_adjustment = Gtk.Adjustment(0, 0, 99, 1, 10, 0)
        self.filter_low.set_property("adjustment", low_adjustment)

        low_spin = Gtk.TreeViewColumn("Random Number", self.filter_low, text=1)
        treeview.append_column(low_spin)

        self.add(treeview)

    def low_on_amount_edited(self, widget, path, value):
        value = int(value)
        self.liststore[path][1] = value
        self.GUI.set_label(str(value))

class GUI:

    def __init__(self):
        self.win = Gtk.Window()
        self.window_grid = Gtk.Grid()
        self.special_box = Gtk.Box(spacing=10)
        self.label = Gtk.Label("Number label")
        self.win.connect("delete-event", Gtk.main_quit)
        self.start_window()

    def start_window(self):
        self.special_box.pack_start(SpecialBox(self), True, True, 0)
        self.window_grid.add(self.special_box)
        self.window_grid.add(self.label)
        self.win.add(self.window_grid)
        self.win.show_all()

    def set_label(self, value):
        self.label.destroy()
        self.label = Gtk.Label(value)
        self.window_grid.add(self.label)
        self.win.show_all()

    def restart_window(self, label="Number"):
        self.window_grid.destroy()
        self.window_grid = Gtk.Grid()
        self.special_box = Gtk.Box(spacing=10)
        self.label = Gtk.Label(label)
        self.start_window()

def main():
    app = GUI()
    Gtk.main()

if __name__ == "__main__":
    sys.exit(main())