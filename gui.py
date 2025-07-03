# gui.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from stego import crypto, embedder, extractor


class StegoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Hide & Seek – Steganography Tool")
        self.root.geometry("500x400")
        self.build_tabs()

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
        # Image path input
        ttk.Label(self.tab_hide, text="Input Image:").pack(pady=5)
        self.input_path = tk.StringVar()
        tk.Entry(self.tab_hide, textvariable=self.input_path, width=50).pack()
        ttk.Button(self.tab_hide, text="Browse", command=self.browse_input).pack()

        # Message input
        ttk.Label(self.tab_hide, text="Message to Hide:").pack(pady=5)
        self.message_entry = tk.Text(self.tab_hide, height=4)
        self.message_entry.pack()

        # Password
        ttk.Label(self.tab_hide, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.tab_hide, show="*")
        self.password_entry.pack()

        ttk.Label(self.tab_hide, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = tk.Entry(self.tab_hide, show="*")
        self.confirm_password_entry.pack()

        # Output path + Hide Button
        ttk.Button(self.tab_hide, text="Hide Message", command=self.hide_message).pack(pady=10)

    def build_extract_tab(self):
        # Stego image path input
        ttk.Label(self.tab_extract, text="Stego Image:").pack(pady=5)
        self.extract_path = tk.StringVar()
        tk.Entry(self.tab_extract, textvariable=self.extract_path, width=50).pack()
        ttk.Button(self.tab_extract, text="Browse", command=self.browse_stego).pack()

        # Password
        ttk.Label(self.tab_extract, text="Password:").pack(pady=5)
        self.extract_password_entry = tk.Entry(self.tab_extract, show="*")
        self.extract_password_entry.pack()

        # Extract Button
        ttk.Button(self.tab_extract, text="Extract Message", command=self.extract_message).pack(pady=10)

        # Output field
        self.result_text = tk.Text(self.tab_extract, height=6, state='disabled')
        self.result_text.pack(pady=5)

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
