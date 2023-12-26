import os
import brotli
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from io import BytesIO
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


class OSecure:
    def __init__(self, root):
        self.root = root
        icon_data = self.get_logo("https://i.imgur.com/wcBAggh.png")
        if icon_data:
            icon_image = Image.open(BytesIO(icon_data))
            icon_image = icon_image.resize((32, 32), Image.ANTIALIAS)
            self.icon_photo = ImageTk.PhotoImage(icon_image)
            self.root.iconphoto(False, self.icon_photo)
        self.root.title("OSecure V1.0")
        self.root.tk_setPalette(background='#2e2e2e', foreground='#ffffff')
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x_position = (screen_width - 400) // 2
        y_position = (screen_height - 300) // 2
        self.root.geometry(f"400x330+{x_position}+{y_position}")
        self.use_compression_var = tk.IntVar()
        self.use_compression_checkbox = tk.Checkbutton(root, text="Use Compression", variable=self.use_compression_var, command=self.update_checkbox_text)
        self.use_compression_checkbox.pack(pady=5)
        self.checkbox_text_var = tk.StringVar()
        self.checkbox_text_label = tk.Label(root, textvariable=self.checkbox_text_var, fg='#ffffff', bg='#2e2e2e')
        self.checkbox_text_label.pack(pady=5)
        self.update_checkbox_text()
        self.filepath_label = tk.Label(root, text="Select a File, or Folder:")
        self.filepath_label.pack(pady=5)
        self.filepath_var = tk.StringVar()
        self.filepath_entry = tk.Entry(root, textvariable=self.filepath_var, state="disabled", width=40)
        self.filepath_entry.pack(pady=5)
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)
        self.password_label = tk.Label(root, text="Enter A Password:")
        self.password_label.pack(pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(root, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=5)
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)
        self.encrypt_button = tk.Button(button_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(side="left", padx=5)
        self.decrypt_button = tk.Button(button_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(side="left", padx=5)
        self.about_button = tk.Button(root, text="About OSecure", command=self.show_about_dialog)
        self.about_button.pack(pady=10)
        
    def get_logo(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            print(f"Error downloading image: {e}")
            return None

    def update_checkbox_text(self):
        if self.use_compression_var.get():
            self.checkbox_text_var.set("Brotli compression is Enabled.")
        else:
            self.checkbox_text_var.set("Brotli compression is Disabled.")

    def browse_file(self):
        self.root.tk_setPalette(background='#2e2e2e', foreground='#ffffff')  # Set dark theme for file dialog
        selected_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if selected_path:
            self.filepath_var.set(selected_path)
        else:
            selected_path = filedialog.askdirectory()
            if selected_path:
                self.filepath_var.set(selected_path)

    def encrypt_file(self):
        selected_path = self.filepath_var.get()
        password = self.password_var.get().encode('utf-8')
        use_compression = bool(self.use_compression_var.get())
        if os.path.isfile(selected_path):
            with open(selected_path, 'rb') as file:
                plaintext = file.read()
            key = self.check_key(password)
            if use_compression:
                plaintext = self.compress_data(plaintext)
            encrypted_data = self.encrypt(plaintext, key)
            with open(selected_path + ".enc", 'wb+') as encrypted_file:
                encrypted_file.write(encrypted_data)
            os.remove(selected_path)
            messagebox.showinfo("Encryption", "File encrypted successfully!")
        elif os.path.isdir(selected_path):
            for filename in os.listdir(selected_path):
                filepath = os.path.join(selected_path, filename)
                if os.path.isfile(filepath):
                    with open(filepath, 'rb') as file:
                        plaintext = file.read()
                    key = self.check_key(password)
                    if use_compression:
                        plaintext = self.compress_data(plaintext)
                    encrypted_data = self.encrypt(plaintext, key)
                    with open(filepath + ".enc", 'wb+') as encrypted_file:
                        encrypted_file.write(encrypted_data)
                    os.remove(filepath)
            messagebox.showinfo("Encryption", "All files in the folder encrypted successfully!")
        else:
            messagebox.showwarning("Invalid Selection", "Please select a valid file, or folder.")

    def decrypt_file(self):
        selected_path = self.filepath_var.get()
        password = self.password_var.get().encode('utf-8')
        use_compression = bool(self.use_compression_var.get())
        if os.path.isfile(selected_path):
            with open(selected_path, 'rb') as file:
                ciphertext = file.read()
            key = self.check_key(password)
            decrypted_data = self.decrypt(ciphertext, key)
            if use_compression:
                decrypted_data = self.decompress_data(decrypted_data)
            with open(selected_path[:-4], 'wb+') as decrypted_file:
                decrypted_file.write(decrypted_data)
            os.remove(selected_path)
            messagebox.showinfo("Decryption", "File decrypted successfully!")
        elif os.path.isdir(selected_path):
            for filename in os.listdir(selected_path):
                if filename.endswith(".enc"):
                    filepath = os.path.join(selected_path, filename)
                    with open(filepath, 'rb') as file:
                        ciphertext = file.read()
                    key = self.check_key(password)
                    decrypted_data = self.decrypt(ciphertext, key)
                    if use_compression:
                        decrypted_data = self.decompress_data(decrypted_data)
                    with open(filepath[:-4], 'wb+') as decrypted_file:
                        decrypted_file.write(decrypted_data)
                    os.remove(filepath)
            messagebox.showinfo("Decryption", "All files in the folder decrypted successfully!")
        else:
            messagebox.showwarning("Invalid Selection", "Please select a valid file or folder.")

    def check_key(self, key):
        key_length = len(key)
        if key_length == 32:
            return key
        elif key_length < 32:
            return key + b' ' * (32 - key_length)
        else:
            return key[:32]

    def encrypt(self, plaintext, key):
        nonce = get_random_bytes(24)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    def decrypt(self, ciphertext, key):
        nonce = ciphertext[:24]
        tag = ciphertext[24:40]
        ciphertext = ciphertext[40:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError as e:
            print(f"Decryption error: {e}")
            return b''

    def compress_data(self, data):
        compressed_data = brotli.compress(data)
        return compressed_data

    def decompress_data(self, compressed_data):
        decompressed_data = brotli.decompress(compressed_data)
        return decompressed_data

    def show_about_dialog(self):
        about_info = (
            "Version 1.0.0.0\n\n"
            "Created by Th3Tr1ckst3r @ github.com.\n\n"
            "This application allows you to encrypt, and decrypt files & folders using secure XChaCha20 encryption.\n\n"
            "You can choose to enable compression to reduce file size. Optimized using Google's Brotli compression algorithm.\n"
        )
        messagebox.showinfo("About OSecure", about_info)


if __name__ == "__main__":
    root = tk.Tk()
    app = OSecure(root)
    root.mainloop()
