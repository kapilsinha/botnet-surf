import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

class Button(Gtk.Box):

    def __init__(self, message, label, window_grid):
        Gtk.Box.__init__(self, spacing=6)
        self.set_border_width(10)
        self.label = label
        self.window_grid = window_grid

        button = Gtk.Button.new_with_label(message)
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        # Change/update a label in the window_grid
        #self.label.label.set_text("Changed the lable")
        self.label.destroy()
        # Add a new label to the window_grid
        new_label = LabelBox("New label")
        self.window_grid.attach(new_label, 0, 2, 1, 1)
        new_label.show_all()

class LabelBox(Gtk.Box):

    def __init__(self, message):
        Gtk.Box.__init__(self, spacing=6)
        self.set_border_width(10)
        self.label = Gtk.Label(message)
        self.pack_start(self.label, True, True, 0)

win = Gtk.Window()
window_grid = Gtk.Grid()

label = LabelBox("This is a label")
button = Button("Test", label, window_grid)

window_grid.attach(label, 0, 0, 1, 1)
window_grid.attach(button, 0, 1, 1, 1)

win.add(window_grid)
win.connect("destroy", Gtk.main_quit)
win.show_all()

Gtk.main()