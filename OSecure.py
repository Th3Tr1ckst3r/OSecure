"""
    OSecure - OSecure is a simple, cross-platform application to make open source data security easy for anyone to use.
    Created by Adrian Tarver(Th3Tr1ckst3r) @ https://github.com/Th3Tr1ckst3r/

////////////////////////////////////////////////////////////////////////////////////////

  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.

  By downloading, copying, installing, or using the software you agree to this license.
  If you do not agree to this license, do not download, install,
  copy, or use the software.


                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU Affero General Public License is a free, copyleft license for
software and other kinds of works, specifically designed to ensure
cooperation with the community in the case of network server software.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
our General Public Licenses are intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  Developers that use our General Public Licenses protect your rights
with two steps: (1) assert copyright on the software, and (2) offer
you this License which gives you legal permission to copy, distribute
and/or modify the software.

  A secondary benefit of defending all users' freedom is that
improvements made in alternate versions of the program, if they
receive widespread use, become available for other developers to
incorporate.  Many developers of free software are heartened and
encouraged by the resulting cooperation.  However, in the case of
software used on network servers, this result may fail to come about.
The GNU General Public License permits making a modified version and
letting the public access it on a server without ever releasing its
source code to the public.

  The GNU Affero General Public License is designed specifically to
ensure that, in such cases, the modified source code becomes available
to the community.  It requires the operator of a network server to
provide the source code of the modified version running there to the
users of that server.  Therefore, public use of a modified version, on
a publicly accessible server, gives the public access to the source
code of the modified version.

  An older license, called the Affero General Public License and
published by Affero, was designed to accomplish similar goals.  This is
a different license, not a version of the Affero GPL, but Affero has
released a new version of the Affero GPL which permits relicensing under
this license.

  The precise terms and conditions for copying, distribution and
modification follow here:

https://raw.githubusercontent.com/Th3Tr1ckst3r/OSecure/main/LICENSE

"""
import os
import brotli
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from tkinter import messagebox, filedialog
from tkinter import *


class OSecure:
    def __init__(self, root):
        self.root = root
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x_position = (screen_width - 400) // 2
        y_position = (screen_height - 300) // 2
        self.root.iconphoto(False, PhotoImage(file=os.path.abspath(os.path.join(os.path.dirname(__file__), "logo.png"))))
        self.root.title("OSecure V1.0")
        self.root.tk_setPalette(background='#2e2e2e', foreground='#ffffff')
        self.root.geometry(f"400x330+{x_position}+{y_position}")
        self.root.resizable(False, False)
        self.use_compression_var = IntVar()
        self.use_compression_checkbox = Checkbutton(root, text="Use Compression", variable=self.use_compression_var, command=self.update_compression_text)
        self.use_compression_checkbox.pack(pady=5)
        self.checkbox_text_var = StringVar()
        self.checkbox_text_label = Label(root, textvariable=self.checkbox_text_var, fg='#ffffff', bg='#2e2e2e')
        self.checkbox_text_label.pack(pady=5)
        self.update_compression_text()
        self.filepath_label = Label(root, text="Select a File, or Folder:")
        self.filepath_label.pack(pady=5)
        self.filepath_var = StringVar()
        self.filepath_entry = Entry(root, textvariable=self.filepath_var, state="disabled", width=40)
        self.filepath_entry.pack(pady=5)
        self.browse_button = Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack(pady=5)
        self.password_label = Label(root, text="Enter A Password:")
        self.password_label.pack(pady=5)
        self.password_var = StringVar() 
        self.password_entry = Entry(root, textvariable=self.password_var, show="*")
        self.password_entry.pack(pady=5)
        button_frame = Frame(root)
        button_frame.pack(pady=5)
        self.encrypt_button = Button(button_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(side="left", padx=5)
        self.decrypt_button = Button(button_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(side="left", padx=5)
        self.about_button = Button(root, text="About OSecure", command=self.show_about_dialog)
        self.about_button.pack(pady=10)
        
    def update_compression_text(self):
        if self.use_compression_var.get():
            self.checkbox_text_var.set("Brotli compression is Enabled.")
        else:
            self.checkbox_text_var.set("Brotli compression is Disabled.")

    def browse_file(self):
        self.root.tk_setPalette(background='#2e2e2e', foreground='#ffffff')
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
    root = Tk()
    app = OSecure(root)
    root.mainloop()
