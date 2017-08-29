import sys
from time import sleep
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

class LoopButton(Gtk.Box):

    def __init__(self, GUI):
        Gtk.Box.__init__(self)

        self.GUI = GUI
        self.set_border_width(10)
        self.message = "1"

        button = Gtk.Button.new_with_label("Run")
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        msg = int(self.message)
        while self.GUI.is_paused == False:
            self.GUI.restart_window(str(msg))
            msg += 1
            while Gtk.events_pending():
                Gtk.main_iteration()
            sleep(1)
        self.GUI.is_paused = True

class PauseButton(Gtk.Box):
    def __init__(self, GUI):
        Gtk.Box.__init__(self)

        self.GUI = GUI
        self.set_border_width(10)

        button = Gtk.Button.new_with_label("Pause")
        button.connect("clicked", self.on_click)
        self.pack_start(button, True, True, 0)

    def on_click(self, widget):
        self.GUI.is_paused = True
        

class GUI:

    def __init__(self):
        self.is_paused = False
        self.win = Gtk.Window()
        self.window_grid = Gtk.Grid()
        self.box = Gtk.Box(spacing=10)
        self.label = Gtk.Label("Default label")
        self.win.connect("delete-event", Gtk.main_quit)
        self.start_window()

    def start_window(self):
        self.box.pack_start(LoopButton(self), True, True, 0)
        self.box.pack_start(PauseButton(self), True, True, 0)
        self.window_grid.add(self.box)
        self.window_grid.add(self.label)
        self.win.add(self.window_grid)
        self.win.show_all()

    def restart_window(self, label="Default label"):
        self.window_grid.destroy()
        self.window_grid = Gtk.Grid()
        self.box = Gtk.Box(spacing=10)
        self.label = Gtk.Label(label)
        self.start_window()

def main():
    app = GUI()
    Gtk.main()

if __name__ == "__main__":
    sys.exit(main())