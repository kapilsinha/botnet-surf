import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
import sys

class GUI:
    def __init__(self):

        self.win = Gtk.Window()
        self.window_grid = Gtk.Grid()
        box = Gtk.Box()

        button = Gtk.Button.new_with_label("Test")
        button.connect("clicked", self.on_click)

        self.label = Gtk.Label("This is a label")

        self.window_grid.attach(self.label, 0, 0, 1, 1)
        self.window_grid.attach(button, 0, 1, 2, 2)

        self.win.add(self.window_grid)

        self.win.connect("delete-event", Gtk.main_quit)
        self.win.show_all()

    def on_click(self, widget):
        # Change/update a label in the window_grid
        self.label.set_label('Label changed')
        #label = Gtk.Label("Another label")
        #self.window_grid.attach(label, 2, 1, 2, 2)
        self.win.show_all()


def main():
    app = GUI()
    Gtk.main()

if __name__ == "__main__":
    sys.exit(main())