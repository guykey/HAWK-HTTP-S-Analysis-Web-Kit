import tkinter as tk
from tkinter import messagebox

value = str()

class PacketEditor(tk.Tk):
    def __init__(self, text=""):
        super().__init__()

        self.title = "PacketEditor"
        self.protocol("WM_DELETE_WINDOW", lambda: self.exit_editor())

        self.text_area = tk.Text(self, wrap='word')
        self.exit_btn = tk.Button(self, text="Send", command=lambda: self.exit_editor())

        self.text_area.insert(tk.END, text)

        self.exit_btn.pack(expand=True, fill='both')
        self.text_area.pack(expand=1, fill='both')

        self.text = ""
        
        self.mainloop()

    def exit_editor(self, used_enter=False):
        self.text = self.text_area.get("1.0", "end-1c")

        if used_enter:
            self.text = self.text[:-1]

        self.destroy()

    def get_text(self):
        return self.text


if __name__ == "__main__":
    pe = PacketEditor()

    print(pe.get_text())
