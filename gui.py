import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from stego import crypto, embedder, extractor


class StegoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Hide & Seek – Steganography Tool")
        self.root.geometry("550x450")
        self.set_dark_mode()
        self.build_tabs()

    def set_dark_mode(self):
        self.root.configure(bg="#2b2b2b")
        style = ttk.Style(self.root)
        style.theme_use("default")

        style.configure("TNotebook", background="#2b2b2b", borderwidth=0)
        style.configure("TNotebook.Tab", background="#444", foreground="#fff", padding=10)
        style.map("TNotebook.Tab", background=[("selected", "#222")])

        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
        style.configure("TEntry", fieldbackground="#3c3f41", foreground="#ffffff")
        style.configure("TButton", background="#3c3f41", foreground="#ffffff")
        style.configure("TCheckbutton", background="#2b2b2b", foreground="#ffffff")

    def build_tabs(self):
        tab_control = ttk.Notebook(self.root)

        self.tab_hide = ttk.Frame(tab_control)
        self.tab_extract = ttk.Frame(tab_control)

        tab_control.add(self.tab_hide, text="Hide Message")
        tab_control.add(self.tab_extract, text="Extract Message")
        tab_control.pack(expand=1, fill="both")

        self.build_hide_tab()
        self.build_extract_tab()

    def build_hide_tab(self):
        padding = {'padx': 10, 'pady': 5}

        ttk.Label(self.tab_hide, text="Input Image:").grid(row=0, column=0, sticky="w", **padding)
        self.input_path = tk.StringVar()
        tk.Entry(self.tab_hide, textvariable=self.input_path, width=50, bg="#3c3f41", fg="#ffffff", insertbackground="white").grid(row=0, column=1, **padding)
        ttk.Button(self.tab_hide, text="Browse", command=self.browse_input).grid(row=0, column=2, **padding)

        ttk.Label(self.tab_hide, text="Message to Hide:").grid(row=1, column=0, sticky="nw", **padding)
        self.message_entry = tk.Text(self.tab_hide, height=4, width=50, bg="#3c3f41", fg="#ffffff", insertbackground="white")
        self.message_entry.grid(row=1, column=1, columnspan=2, **padding)

        ttk.Label(self.tab_hide, text="Password:").grid(row=2, column=0, sticky="w", **padding)
        self.password_entry = tk.Entry(self.tab_hide, show="*", width=30, bg="#3c3f41", fg="#ffffff", insertbackground="white")
        self.password_entry.grid(row=2, column=1, sticky="w", **padding)

        self.show_password_var = tk.BooleanVar()
        show_pass_cb = ttk.Checkbutton(self.tab_hide, text="Show", variable=self.show_password_var, command=self.toggle_password_visibility)
        show_pass_cb.grid(row=2, column=2, sticky="w", **padding)

        ttk.Label(self.tab_hide, text="Confirm Password:").grid(row=3, column=0, sticky="w", **padding)
        self.confirm_password_entry = tk.Entry(self.tab_hide, show="*", width=30, bg="#3c3f41", fg="#ffffff", insertbackground="white")
        self.confirm_password_entry.grid(row=3, column=1, sticky="w", **padding)

        self.show_confirm_var = tk.BooleanVar()
        show_confirm_cb = ttk.Checkbutton(self.tab_hide, text="Show", variable=self.show_confirm_var, command=self.toggle_confirm_visibility)
        show_confirm_cb.grid(row=3, column=2, sticky="w", **padding)

        ttk.Button(self.tab_hide, text="Hide Message", command=self.hide_message).grid(row=4, column=1, pady=20)

    def build_extract_tab(self):
        padding = {'padx': 10, 'pady': 5}

        ttk.Label(self.tab_extract, text="Stego Image:").grid(row=0, column=0, sticky="w", **padding)
        self.extract_path = tk.StringVar()
        tk.Entry(self.tab_extract, textvariable=self.extract_path, width=50, bg="#3c3f41", fg="#ffffff", insertbackground="white").grid(row=0, column=1, **padding)
        ttk.Button(self.tab_extract, text="Browse", command=self.browse_stego).grid(row=0, column=2, **padding)

        ttk.Label(self.tab_extract, text="Password:").grid(row=1, column=0, sticky="w", **padding)
        self.extract_password_entry = tk.Entry(self.tab_extract, show="*", width=30, bg="#3c3f41", fg="#ffffff", insertbackground="white")
        self.extract_password_entry.grid(row=1, column=1, sticky="w", **padding)

        self.show_extract_password_var = tk.BooleanVar()
        show_extract_cb = ttk.Checkbutton(self.tab_extract, text="Show", variable=self.show_extract_password_var, command=self.toggle_extract_visibility)
        show_extract_cb.grid(row=1, column=2, sticky="w", **padding)

        ttk.Button(self.tab_extract, text="Extract Message", command=self.extract_message).grid(row=2, column=1, pady=20)

        ttk.Label(self.tab_extract, text="Decrypted Message:").grid(row=3, column=0, sticky="nw", **padding)
        self.result_text = tk.Text(self.tab_extract, height=6, width=50, bg="#3c3f41", fg="#ffffff", insertbackground="white", state='disabled')
        self.result_text.grid(row=3, column=1, columnspan=2, **padding)

    def toggle_password_visibility(self):
        show = "" if self.show_password_var.get() else "*"
        self.password_entry.config(show=show)

    def toggle_confirm_visibility(self):
        show = "" if self.show_confirm_var.get() else "*"
        self.confirm_password_entry.config(show=show)

    def toggle_extract_visibility(self):
        show = "" if self.show_extract_password_var.get() else "*"
        self.extract_password_entry.config(show=show)

    def browse_input(self):
        file_path = filedialog.askopenfilename(title="Choose an Image", filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.input_path.set(file_path)

    def browse_stego(self):
        file_path = filedialog.askopenfilename(title="Choose Stego Image", filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.extract_path.set(file_path)

    def hide_message(self):
        input_path = self.input_path.get()
        message = self.message_entry.get("1.0", "end").strip()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not input_path or not message or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", title="Save Stego Image As")
        if not output_path:
            return

        try:
            aes = crypto.AESCipher(password)
            ciphertext = aes.encrypt(message.encode("utf-8"))
            embedder.embed_message_into_image(input_path, ciphertext, output_path)
            messagebox.showinfo("Success", f"Message successfully embedded in {output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_message(self):
        image_path = self.extract_path.get()
        password = self.extract_password_entry.get()

        if not image_path or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            ciphertext = extractor.extract_message_from_image(image_path)
            aes = crypto.AESCipher(password)
            plaintext = aes.decrypt(ciphertext)
            self.result_text.configure(state='normal')
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", plaintext.decode("utf-8", errors="replace"))
            self.result_text.configure(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = StegoGUI(root)
    root.mainloop()
