import os
import base64
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from encryption import encrypt_file, decrypt_file, encrypt_text, decrypt_text, save_text
import pathlib

class encryption_gui(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Encryption App")
        self.master.resizable(False, False)

        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.password = tk.StringVar()
        self.input_file_dec = tk.StringVar()
        self.output_file_dec = tk.StringVar()
        self.password_dec = tk.StringVar()
        self.input_text = tk.StringVar()
        self.output_text = tk.StringVar()
        self.output_text_dec = tk.StringVar()
        self.password_textdec = tk.StringVar()
        self.password_text = tk.StringVar()
        self.output_text = tk.StringVar()
        self.password_secsave = tk.StringVar()
        self.password_save = tk.StringVar()
        self.password_secload = tk.StringVar()
        self.password_load = tk.StringVar()

        # Crear widgets
        self.notebook = ttk.Notebook(self.master)

        # Crear pestañas
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        self.tab4 = ttk.Frame(self.notebook)
        self.tab5 = ttk.Frame(self.notebook)
        self.tab6 = ttk.Frame(self.notebook)
        self.tab7 = ttk.Frame(self.notebook)

        # Agregar pestañas al notebook
        self.notebook.add(self.tab1, text="Encrypt File")
        self.notebook.add(self.tab2, text="Decrypt File")
        self.notebook.add(self.tab3, text="Encrypt Text")
        self.notebook.add(self.tab4, text="Decrypt Text")
        self.notebook.add(self.tab5, text="Generate Key")
        self.notebook.add(self.tab6, text="Save Password")
        self.notebook.add(self.tab7, text="Load Password")

        # Pestaña 1
        self.input_label = ttk.Label(self.tab1, text="Input file:")
        self.input_entry = ttk.Entry(self.tab1, textvariable=self.input_file, width=40)
        self.browse_input_button = ttk.Button(self.tab1, text="Browse", command=self.browse_input_file)
        self.output_label = ttk.Label(self.tab1, text="Output file:")
        self.output_entry = ttk.Entry(self.tab1, textvariable=self.output_file, width=40)
        self.browse_output_button = ttk.Button(self.tab1, text="Browse", command=self.browse_output_file)
        self.password_label = ttk.Label(self.tab1, text="Password:")
        self.password_entry = ttk.Entry(self.tab1, show="*", textvariable=self.password, width=40)
        self.encrypt_button = ttk.Button(self.tab1, text="Encrypt", command=self.encrypt)

        # Dispocición en grilla para pestaña 1
        self.input_label.grid(row=0, column=0, sticky="e")
        self.input_entry.grid(row=0, column=1)
        self.browse_input_button.grid(row=0, column=2)
        self.output_label.grid(row=1, column=0, sticky="e")
        self.output_entry.grid(row=1, column=1)
        self.browse_output_button.grid(row=1, column=2)
        self.password_label.grid(row=2, column=0, sticky="e")
        self.password_entry.grid(row=2, column=1)
        self.encrypt_button.grid(row=3, column=0)

        # Pestaña 2
        self.input_label_dec = ttk.Label(self.tab2, text="Input file:")
        self.input_entry_dec = ttk.Entry(self.tab2, textvariable=self.input_file_dec, width=40)
        self.browse_input_button_dec = ttk.Button(self.tab2, text="Browse", command=self.browse_input_file_dec)
        self.output_label_dec = ttk.Label(self.tab2, text="Output file:")
        self.output_entry_dec = ttk.Entry(self.tab2, textvariable=self.output_file_dec, width=40)
        self.browse_output_button_dec = ttk.Button(self.tab2, text="Browse", command=self.browse_output_file_dec)
        self.password_label_dec = ttk.Label(self.tab2, text="Password:")
        self.password_entry_dec = ttk.Entry(self.tab2, show="*", textvariable=self.password_dec, width=40)
        self.decrypt_button = ttk.Button(self.tab2, text="Decrypt", command=self.decrypt)

        # Dispocición en grilla para pestaña 2
        self.input_label_dec.grid(row=0, column=0, sticky="e")
        self.input_entry_dec.grid(row=0, column=1)
        self.browse_input_button_dec.grid(row=0, column=2)
        self.output_label_dec.grid(row=1, column=0, sticky="e")
        self.output_entry_dec.grid(row=1, column=1)
        self.browse_output_button_dec.grid(row=1, column=2)
        self.password_label_dec.grid(row=2, column=0, sticky="e")
        self.password_entry_dec.grid(row=2, column=1)
        self.decrypt_button.grid(row=3, column=0)

        # Pestaña 3
        self.input_text_label = ttk.Label(self.tab3, text="Input text:")
        self.input_text_entry = tk.Text(self.tab3, height=10, width=40)
        self.output_text_label = ttk.Label(self.tab3, text="Output text:")
        self.output_text_entry = tk.Text(self.tab3, height=10, width=40, state="disabled")
        self.password_label_text = ttk.Label(self.tab3, text="Password:")
        self.password_entry_text = ttk.Entry(self.tab3, show="*", textvariable=self.password_text, width=40)
        self.encrypt_text_button = ttk.Button(self.tab3, text="Encrypt Text", command=self.encrypt_text)
        self.save_button = ttk.Button(self.tab3, text="Sava encrypted text to file", command=self.save_encrypted_text)

        # Dispocición en grilla para pestaña 3
        self.input_text_label.grid(row=1, column=0, sticky="e")
        self.input_text_entry.grid(row=1, column=1)
        self.output_text_label.grid(row=2, column=0, sticky="e")
        self.output_text_entry.grid(row=2, column=1)
        self.password_label_text.grid(row=3, column=0, sticky="e")
        self.password_entry_text.grid(row=3, column=1)
        self.encrypt_text_button.grid(row=4, column=0)
        self.save_button.grid(row=4, column=1)


        # Pestaña 4
        self.input_text_dec_label = ttk.Label(self.tab4, text="Input text:")
        self.input_text_dec_entry = tk.Text(self.tab4, height=10, width=40)
        self.output_text_dec_label = ttk.Label(self.tab4, text="Output text:")
        self.output_text_dec_entry = tk.Text(self.tab4, height=10, width=40, state="disabled")
        self.password_label_textdec = ttk.Label(self.tab4, text="Password:")
        self.password_entry_textdec = ttk.Entry(self.tab4, show="*", textvariable=self.password_textdec, width=40)
        self.decrypt_text_button = ttk.Button(self.tab4, text="Decrypt Text", command=self.decrypt_text)

        # Dispocición en grilla para pestaña 4
        self.input_text_dec_label.grid(row=1, column=0, sticky="e")
        self.input_text_dec_entry.grid(row=1, column=1)
        self.output_text_dec_label.grid(row=2, column=0, sticky="e")
        self.output_text_dec_entry.grid(row=2, column=1)
        self.password_label_textdec.grid(row=3, column=0, sticky="e")
        self.password_entry_textdec.grid(row=3, column=1)
        self.decrypt_text_button.grid(row=4, column=0)

        # Pestaña 5
        def generate_key():
            key = base64.b64encode(os.urandom(24)).decode('utf-8')
            self.output_text.set(key)

        self.generate_button = ttk.Button(self.tab5, text="Generate Key", command=generate_key)
        self.output_label = ttk.Label(self.tab5, text="Generated Key:")
        self.output_entry = ttk.Entry(self.tab5, textvariable=self.output_text, width=50, state="readonly")

        # Dispocición en grilla para pestaña 5
        self.output_label.grid(row=0, column=0)
        self.output_entry.grid(row=0, column=1, sticky="e")
        self.generate_button.grid(row=1, column=0)

        # Pestaña 6
        self.label_secsave_password = ttk.Label(self.tab6, text="Security Password:")
        self.entry_secsave_password = ttk.Entry(self.tab6, width=50, textvariable=self.password_secsave)
        self.label_save_password = ttk.Label(self.tab6, text="Password to save:")
        self.entry_save_password = ttk.Entry(self.tab6, width=50, textvariable=self.password_save)
        self.button_save_password = ttk.Button(self.tab6, text="Save Password", command=self.save_password)

        # Dispocición en grilla para pestaña 6
        self.label_secsave_password.grid(row=0, column=0)
        self.entry_secsave_password.grid(row=0, column=1, sticky="e")
        self.label_save_password.grid(row=1, column=0)
        self.entry_save_password.grid(row=1, column=1, sticky="e")
        self.button_save_password.grid(row=2, column=0)

        # Pestaña 7
        self.label_secload_password = ttk.Label(self.tab7, text="Security Password:")
        self.entry_secload_password = ttk.Entry(self.tab7, width=50, textvariable=self.password_secload)
        self.label_load_password = ttk.Label(self.tab7, text="Password:")
        self.entry_load_password = ttk.Entry(self.tab7, textvariable=self.password_load, width=50, state="readonly")
        self.button_load_password = ttk.Button(self.tab7, text="Load Password", command=self.load_password)

        # Dispocición en grilla para pestaña 7
        self.label_secload_password.grid(row=0, column=0)
        self.entry_secload_password.grid(row=0, column=1, sticky="e")
        self.button_load_password.grid(row=1, column=0)
        self.label_load_password.grid(row=2, column=0)
        self.entry_load_password.grid(row=2, column=1, sticky="e")

        self.notebook.pack()

    # Funciones para explorar los archivos de entrada y salida
    def browse_input_file(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select the input file")
        if filename:
            self.input_file.set(filename)

    def browse_output_file(self):
        split_file = os.path.splitext(os.path.basename(self.input_file.get()))
        filename = filedialog.asksaveasfilename(initialdir=os.getcwd(), title="Select the output file", initialfile=split_file[0]+split_file[1]+'.enc', defaultextension='.enc', filetypes=[('Encoded File', '*.enc')])
        if filename:
            self.output_file.set(filename)

    def browse_input_file_dec(self):
        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select the input file", filetypes=[('Encoded File', '*.enc')])
        if filename:
            self.input_file_dec.set(filename)

    def browse_output_file_dec(self):
        split_file = os.path.splitext(os.path.basename(self.input_file_dec.get()))
        filename = filedialog.asksaveasfilename(initialdir=os.getcwd(), title="Select the output file", initialfile=split_file[0], defaultextension=os.path.splitext(split_file[0])[1], filetypes=[('Source File Format', '*'+os.path.splitext(split_file[0])[1])])
        if filename:
            self.output_file_dec.set(filename)

    # Funciones de cifrado y decifrado
    def encrypt(self):
        password = self.password.get()
        input_file = self.input_file.get()
        output_file = self.output_file.get()

        if len(password) >= 8 and len(input_file) != 0 and len(output_file) != 0:
            if os.path.exists(input_file):
                try:
                    encrypt_file(password, input_file, output_file)
                    messagebox.showinfo("Encryption", "Encryption successful.")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
            else:
                messagebox.showerror("Error", "Input file does not exist.")
        else:
            messagebox.showerror("Error", "Invalid input. Password should be at least 8 characters long and Input, Output files can't be empty.")

    def decrypt(self):
        password = self.password_dec.get()
        input_file = self.input_file_dec.get()
        output_file = self.output_file_dec.get()

        if len(password) >= 8 and len(input_file) != 0 and len(output_file) != 0:
            if os.path.exists(input_file):
                try:
                    decrypt_file(password, input_file, output_file)
                    messagebox.showinfo("Decryption", "Decryption successful.")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
            else:
                messagebox.showerror("Error", "Input file does not exist.")
        else:
            messagebox.showerror("Error", "Invalid input. Password should be at least 8 characters long and Input, Output files can't be empty.")

    def encrypt_text(self):
        password = self.password_text.get()
        text = self.input_text_entry.get("1.0", tk.END).strip()

        if len(password) >= 8 and len(text) != 0:
            try:
                encrypted_text = encrypt_text(password, text)
                self.output_text.set(base64.b64encode(encrypted_text).decode("utf-8"))
                self.output_text_entry.configure(state="normal")
                self.output_text_entry.delete("1.0", tk.END)
                self.output_text_entry.insert(tk.END, self.output_text.get())
                self.output_text_entry.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Invalid input. Password should be at least 8 characters long and Input text can't be empty.")

    def save_encrypted_text(self):
        password = self.password_text.get()
        input_text = self.input_text_entry.get("1.0", tk.END)
        if len(password) >= 8 and len(input_text) != 0:
            output_file = filedialog.asksaveasfilename(initialdir=os.getcwd(), title = "Select file", initialfile='Encrypted.txt.enc', filetypes=[('Encrypted Text File', '*.txt.enc')])
            try:
                save_text(password, input_text, output_file)
                messagebox.showinfo("Encryption", "Saved the encrypted text successfuly.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Invalid input. Password should be at least 8 characters long and Input text can't be empty.")

    def decrypt_text(self):
        password = self.password_textdec.get()
        text = base64.b64decode(self.input_text_dec_entry.get("1.0", tk.END).strip())

        if len(password) >= 8 and len(text) != 0:
            try:
                decrypted_text = decrypt_text(password, text)
                self.output_text_dec.set(decrypted_text)
                self.output_text_dec_entry.configure(state="normal")
                self.output_text_dec_entry.delete("1.0", tk.END)
                self.output_text_dec_entry.insert(tk.END, self.output_text_dec.get())
                self.output_text_dec_entry.configure(state="disabled")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Invalid input. Password should be at least 8 characters long and Input text can't be empty.")

    def save_password(self):
        sec_password = self.password_secsave.get()
        password = self.password_save.get()

        if len(sec_password) < 8:
            messagebox.showerror("Error", "The security password must be at least 8 characters long.")
            return

        if len(password) == 0:
            messagebox.showerror("Error", "Please enter a password to save.")
            return

        try:
            encrypted_pass = encrypt_text(sec_password, password)
            filename = filedialog.asksaveasfilename(initialdir=os.getcwd(), title="Save Password", initialfile= 'myKey', defaultextension='.password',  filetypes=[('Password File', '*.password')])
            if filename:
                with open(filename, "w") as f:
                    f.write(base64.b64encode(encrypted_pass).decode("utf-8"))
                    messagebox.showinfo("Save Password", "Password saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_password(self):
        sec_password = self.password_secload.get()
        if len(sec_password) < 1:
            messagebox.showerror("Error", "Please enter the Security password.")
            return

        filename = filedialog.askopenfilename(initialdir=os.getcwd(), title="Load Password", filetypes=[('Password File', '*.password')])
        if not filename:
            return
        if not os.path.exists(filename) or os.path.splitext(filename)[1] != ".password":
            messagebox.showerror("Error", "Could not load the password. Please make sure to select a valid .password file.")
            return

        with open(filename, "r") as f:
            password = f.read()
            if not password:
                messagebox.showerror("Error", "The password file is empty.")
                return
            encpass = base64.b64decode(password)

            try:
                decrypted_text = decrypt_text(sec_password, encpass)
                self.password_load.set(decrypted_text)
                messagebox.showinfo("Load Password", "Password loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = encryption_gui(master=root)
    app.mainloop()