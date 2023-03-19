import tkinter as tk
from gui import encryption_gui
try:
    import pyi_splash
    pyi_splash.close()
except ImportError:
    pass

if __name__ == "__main__":
    root = tk.Tk()
    app = encryption_gui(master=root)
    app.mainloop()