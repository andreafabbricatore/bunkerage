import tkinter.filedialog
import tkinter as tk
import tkinter.ttk as ttk
import psycopg2
import os
from Crypto.Cipher import AES
import base64
import math
import PIL
from PIL import Image
import time
import pyperclip
import ast
import requests

class mainApp():
    def __init__(self):
        self.dir = os.getcwd()
        try:
            r = requests.get(url='https://api.npoint.io/d7afdb510babef57198f')
            self.conn = psycopg2.connect(
    dbname=r.json()['dbname'], 
    user=r.json()['user'], 
    password=r.json()['password'], 
    host=r.json()['host']
    )

            self.cur = self.conn.cursor()
            self.conn_status = True
        except:
            self.conn_status = False

        self.root = tk.Tk()
        self.encryption_service = Encryption()
        
        self.root.title("Bunker Client")
        self.root.resizable(False, False)
        self.show_main()
    
    def run(self):
        self.root.mainloop()

    def show_main(self, *args):
        self.root.geometry('500x300')
        screen_frame = tk.Frame(self.root, bg='white')
        screen_frame.place(relwidth=1, relheight=1)

        log_decrypt_frame = tk.Frame(screen_frame, bg='#efeff5')
        log_decrypt_frame.place(relx=0.5, rely=0.05, relwidth=0.95, relheight=0.86, anchor='n')

        choose_label = tk.Label(log_decrypt_frame, text="Login or Decrypt anonymously", bg='#efeff5', fg="black")
        choose_label.config(font=("Calibri", 20))
        choose_label.place(relx=0.5, rely=0.1, anchor='n')

        login_button = tk.Button(log_decrypt_frame, text="Login", relief='flat', command=self.show_login, borderwidth=0, pady=5, padx=20, width=10)
        login_button.place(relx=0.3, rely=0.3, anchor='n')

        decrypt_anon_button = tk.Button(log_decrypt_frame, text="Decrypt", relief='flat', command=self.show_decrypt, borderwidth=0, pady=5, padx=20, width=10)
        decrypt_anon_button.place(relx=0.7, rely=0.3, anchor='n')
        status_tag = tk.Label(screen_frame, text="Online", bg="white", fg="green")
        if self.conn_status:
            status_tag.place(relx=0.9, rely=0.92)
        else:
            status_tag.config(fg="red")
            status_tag.config(text="Offline")
            status_tag.place(relx=0.9, rely=0.92)

    def show_login(self, *args):
        screen_frame_login = tk.Frame(self.root, bg='white')
        screen_frame_login.place(relwidth=1, relheight=1)

        username_val = tk.StringVar()
        username_label = tk.Label(screen_frame_login, text="Username", bg="white", fg="black")
        username_label.place(relx=0.25, rely=0.05, anchor='n')
        self.username_entry = tk.Entry(screen_frame_login, bg='white', relief='flat',fg='black', textvariable=username_val)
        self.username_entry.place(relx=0.12, rely=0.19, anchor='w', relwidth=0.6, relheight=0.1)

        password_val = tk.StringVar()
        psw_label = tk.Label(screen_frame_login, text="Password", bg="white", fg="black")
        psw_label.place(relx=0.25, rely=0.3, anchor='n')
        self.psw_entry = tk.Entry(screen_frame_login, bg='white', relief='flat',fg='black', show='*', textvariable=password_val)
        self.psw_entry.place(relx=0.12, rely=0.44, anchor='w', relwidth=0.6, relheight=0.1)

        submit = tk.Button(screen_frame_login, text="Login", command=self.loginconndb,relief="flat", borderwidth=0, pady=5, padx=5, width=5)
        submit.place(relx=0.12, rely=0.65, anchor='w')

        self.returnhome = tk.Label(screen_frame_login, text="Return Home", bg="white", fg="black")
        self.returnhome.bind("<Button-1>", self.show_main)
        self.returnhome.bind("<Enter>", self.hover_return_home)
        self.returnhome.bind("<Leave>", self.exit_return_home)
        self.returnhome.place(relx=0.12, rely=0.85, anchor='w')

        self.error_login = tk.Label(screen_frame_login, text="", bg="white", fg="red")
        self.error_login.place(relx=0.3, rely=0.61)
        

    def show_decrypt(self):
        self.chosen_decrypt_file = ""
        self.chosen_decrypt_dest = ""
        self.decrypt_key = ""
        self.decrypt_nonce = ""
        self.decrypt_tag = ""
        self.root.geometry('500x250')

        decrypt_frame = tk.Frame(self.root, bg="#efeff5", highlightbackground="black", highlightthickness=1)
        decrypt_frame.place(relwidth=1, relheight=1)

        self.returnhome = tk.Label(decrypt_frame, text="Return Home", bg="#efeff5", fg="black")
        self.returnhome.place(relx=0.8, rely=0.05, anchor="w")
        self.returnhome.bind("<Button-1>", self.show_main)
        self.returnhome.bind("<Enter>", self.hover_return_home)
        self.returnhome.bind("<Leave>", self.exit_return_home)

        decrypttag = tk.Label(decrypt_frame, text="Decrypt", bg="#efeff5", fg="black")
        decrypttag.config(font=("Calibri", 20, "bold"))
        decrypttag.place(rely=0.05, relx=0.05)

        self.selectfiletagdecrypt = tk.Label(decrypt_frame, text="File to Decrypt", bg="#efeff5", fg="black")
        self.selectfiletagdecrypt.place(rely=0.18, relx=0.05)

        self.selectfilebuttondecrypt = tk.Button(decrypt_frame, text="Import", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.importdecryptfile)
        self.selectfilebuttondecrypt.place(rely=0.3, relx=0.057)

        self.selectdesttagdecrypt = tk.Label(decrypt_frame, text="File Destination", bg="#efeff5", fg="black")
        self.selectdesttagdecrypt.place(rely=0.46, relx=0.05)

        self.selectdestbuttondecrypt = tk.Button(decrypt_frame, text="Choose Destination", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.choosedecryptdest)
        self.selectdestbuttondecrypt.place(rely=0.58, relx=0.057)

        self.processlabeldecrypt = tk.Label(decrypt_frame, text="Decrypting...", bg="#efeff5", fg="black")
        self.processlabeldecrypt.config(font=("Calibri", 20, "bold"))

        self.reset_button_decrypt = tk.Button(decrypt_frame, text="Reset", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.resetdecryptloggedapp)

        decryptbutton = tk.Button(decrypt_frame, text="Decrypt", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.dodecrypt)
        decryptbutton.place(rely=0.8, relx=0.057, relwidth=0.886)

        self.importkeystag = tk.Label(decrypt_frame, text="Import Keys", bg="#efeff5", fg="black")
        self.importkeystag.place(rely=0.46, relx=0.595)

        self.importkeysbutton = tk.Button(decrypt_frame, text="Import", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.getkeyswindow)
        self.importkeysbutton.place(rely=0.58, relx=0.6)

        self.error_tag_decrypt = tk.Label(decrypt_frame, text="", bg="#efeff5", fg="red")

    def show_logged_app(self, uid):
        self.chosen_file = ""
        self.chosen_dest = ""
        self.chosen_decrypt_file = ""
        self.chosen_decrypt_dest = ""
        self.decrypt_key = ""
        self.decrypt_nonce = ""
        self.decrypt_tag = ""
        self.root.geometry('500x500')

        logged_app_frame = tk.Frame(self.root, bg='white')
        logged_app_frame.place(relwidth=1, relheight=1)

        title_frame = tk.Frame(logged_app_frame, bg="#efeff5", highlightbackground="black", highlightthickness=1)
        title_frame.place(relwidth=1, relheight=0.1, rely=0, relx=0)

        welcometag = tk.Label(title_frame, text=("Welcome User: %s" % uid), bg="#efeff5", fg="black")
        welcometag.place(relx=0.05, rely=0.5, anchor='w')

        self.logouttag = tk.Label(title_frame, text="Logout", bg="#efeff5", fg="black")
        self.logouttag.place(relx=0.85, rely=0.5, anchor="w")
        self.logouttag.bind("<Button-1>", self.show_main)
        self.logouttag.bind("<Enter>", self.hover_logout)
        self.logouttag.bind("<Leave>", self.exit_hover_logout)

        encrypt_frame = tk.Frame(logged_app_frame, bg="#efeff5", highlightbackground="black", highlightthickness=1)
        encrypt_frame.place(relwidth=1, relheight=0.45, rely=0.1, relx=0)

        encrypttag = tk.Label(encrypt_frame, text="Encrypt", bg="#efeff5", fg="black")
        encrypttag.config(font=("Calibri", 20, "bold"))
        encrypttag.place(rely=0.05, relx=0.05)

        self.selectfiletag = tk.Label(encrypt_frame, text="File to Encrypt", bg="#efeff5", fg="black")
        self.selectfiletag.place(rely=0.18, relx=0.05)

        self.selectfilebutton = tk.Button(encrypt_frame, text="Import", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.importfile)
        self.selectfilebutton.place(rely=0.3, relx=0.057)

        self.selectdesttag = tk.Label(encrypt_frame, text="File Destination", bg="#efeff5", fg="black")
        self.selectdesttag.place(rely=0.46, relx=0.05)

        self.selectdestinationbutton = tk.Button(encrypt_frame, text="Choose Destination", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.choosedest)
        self.selectdestinationbutton.place(rely=0.58, relx=0.057)

        #self.encryptbar = ttk.Progressbar(self.encrypt_frame, orient="horizontal", length="150", mode="determinate")
        self.processlabel = tk.Label(encrypt_frame, text="Encrypting...", bg="#efeff5", fg="black")
        self.processlabel.config(font=("Calibri", 20, "bold"))
        

        self.show_keys_button = tk.Button(encrypt_frame, text="Show Keys", bg="#efeff5", fg="black", relief="flat", borderwidth=0, pady=3, padx=10, command=self.showkeyswindow)
        self.reset_button = tk.Button(encrypt_frame, text="Reset", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.resetencryptloggedapp)

        encryptbutton = tk.Button(encrypt_frame, text="Encrypt", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.doencrypt)
        encryptbutton.place(rely=0.8, relx=0.057, relwidth=0.886)

        self.error_tag = tk.Label(encrypt_frame, text="", bg="#efeff5", fg="red")

        decrypt_frame = tk.Frame(logged_app_frame, bg="#efeff5", highlightbackground="black", highlightthickness=1)
        decrypt_frame.place(relwidth=1, relheight=0.45, rely=0.55, relx=0)

        decrypttag = tk.Label(decrypt_frame, text="Decrypt", bg="#efeff5", fg="black")
        decrypttag.config(font=("Calibri", 20, "bold"))
        decrypttag.place(rely=0.05, relx=0.05)

        self.selectfiletagdecrypt = tk.Label(decrypt_frame, text="File to Decrypt", bg="#efeff5", fg="black")
        self.selectfiletagdecrypt.place(rely=0.18, relx=0.05)

        self.selectfilebuttondecrypt = tk.Button(decrypt_frame, text="Import", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.importdecryptfile)
        self.selectfilebuttondecrypt.place(rely=0.3, relx=0.057)

        self.selectdesttagdecrypt = tk.Label(decrypt_frame, text="File Destination", bg="#efeff5", fg="black")
        self.selectdesttagdecrypt.place(rely=0.46, relx=0.05)

        self.selectdestbuttondecrypt = tk.Button(decrypt_frame, text="Choose Destination", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.choosedecryptdest)
        self.selectdestbuttondecrypt.place(rely=0.58, relx=0.057)

        self.processlabeldecrypt = tk.Label(decrypt_frame, text="Decrypting...", bg="#efeff5", fg="black")
        self.processlabeldecrypt.config(font=("Calibri", 20, "bold"))

        self.reset_button_decrypt = tk.Button(decrypt_frame, text="Reset", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.resetdecryptloggedapp)

        decryptbutton = tk.Button(decrypt_frame, text="Decrypt", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.dodecrypt)
        decryptbutton.place(rely=0.8, relx=0.057, relwidth=0.886)

        self.importkeystag = tk.Label(decrypt_frame, text="Import Keys", bg="#efeff5", fg="black")
        self.importkeystag.place(rely=0.46, relx=0.595)

        self.importkeysbutton = tk.Button(decrypt_frame, text="Import", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.getkeyswindow)
        self.importkeysbutton.place(rely=0.58, relx=0.6)

        self.error_tag_decrypt = tk.Label(decrypt_frame, text="", bg="#efeff5", fg="red")

    def showkeyswindow(self):
        keyswindow = tk.Toplevel(self.root)
        keyswindow.resizable(False, False)
        keyswindow.title("*Encryption Keys*")
        keyswindow.geometry("700x200")

        keys_frame = tk.Frame(keyswindow, bg='white')
        keys_frame.place(relwidth=1, relheight=1)

        file_label = tk.Label(keys_frame, text="File: %s" % (os.path.basename(self.chosen_file)), bg="white", fg="black")
        file_label.config(font=("Calibri", 13, "bold"))
        file_label.place(rely=0.05, relx=0.02)

        key_label = tk.Label(keys_frame, text="Key: %s" % (str(self.key)[2:-1]), bg="white", fg="black")
        key_label.place(rely=0.2, relx=0.02)

        nonce_label = tk.Label(keys_frame, text="Nonce: %s" % (str(self.nonce)[2:-1]), bg="white", fg="black")
        nonce_label.place(rely=0.33, relx=0.02)

        tag_label = tk.Label(keys_frame, text="Tag: %s" % (str(self.tag)[2:-1]), bg="white", fg="black")
        tag_label.place(rely=0.46, relx=0.02)

        copy_keys_button = tk.Button(
            keys_frame, text="Copy Keys to Clipboard", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, 
            command=pyperclip.copy("File: %s \nKey: %s \nNonce: %s \nTag: %s" % (os.path.basename(self.chosen_file), str(self.key)[2:-1], str(self.nonce)[2:-1], str(self.tag)[2:-1])))
        copy_keys_button.place(rely=0.65, relx=0.02, relwidth=0.96)

    def getkeyswindow(self):
        self.getkeyswindow = tk.Toplevel(self.root)
        self.getkeyswindow.resizable(False,False)
        self.getkeyswindow.title("*Encryption Keys*")
        self.getkeyswindow.geometry("700x220")

        keys_frame = tk.Frame(self.getkeyswindow, bg='white')
        keys_frame.place(relwidth=1, relheight=1)
        if self.chosen_decrypt_file != "":
            file_label = tk.Label(keys_frame, text="File: %s" % (os.path.basename(self.chosen_decrypt_file)), bg="white", fg="black")

            key_val = tk.StringVar()
            key_label = tk.Label(keys_frame, text="Key", bg="white", fg="black")
            key_label.place(rely=0.15, relx=0.02)
            self.key_entry = tk.Entry(keys_frame, bg='white', relief='flat',fg='black', textvariable=key_val)
            self.key_entry.place(rely=0.25, relx=0.02, relwidth=0.96, relheight=0.1)

            nonce_val = tk.StringVar()
            nonce_label = tk.Label(keys_frame, text="Nonce", bg="white", fg="black")
            nonce_label.place(rely=0.35, relx=0.02)
            self.nonce_entry = tk.Entry(keys_frame, bg='white', relief='flat',fg='black', textvariable=nonce_val)
            self.nonce_entry.place(rely=0.45, relx=0.02, relwidth=0.96, relheight=0.1)

            tag_val = tk.StringVar()
            tag_label = tk.Label(keys_frame, text="Tag", bg="white", fg="black")
            tag_label.place(rely=0.55, relx=0.02)
            self.tag_entry = tk.Entry(keys_frame, bg='white', relief='flat',fg='black', textvariable=tag_val)
            self.tag_entry.place(rely=0.65, relx=0.02, relwidth=0.96, relheight=0.1)

            submit_keys_button = tk.Button(keys_frame, text="Submit Keys", bg="#efeff5", fg="black", relief='flat', borderwidth=0, pady=3, padx=10, command=self.get_decrypt_keys)
            submit_keys_button.place(rely=0.8, relx=0.02, relwidth=0.96)

        else:
            file_label = tk.Label(keys_frame, text="Please Choose File First", bg="white", fg="black")
        file_label.config(font=("Calibri", 13, "bold"))
        file_label.place(rely=0.05, relx=0.02)

    def get_decrypt_keys(self):
        self.decrypt_key = self.key_entry.get().strip().encode('latin-1').decode('unicode_escape').encode('latin-1')
        self.decrypt_nonce = self.nonce_entry.get().strip().encode('latin-1').decode('unicode_escape').encode('latin-1')
        self.decrypt_tag = self.tag_entry.get().strip().encode('latin-1').decode('unicode_escape').encode('latin-1')
        print(self.decrypt_key, self.decrypt_nonce, self.decrypt_tag)
        print(type(self.decrypt_tag), type(self.decrypt_nonce), type(self.decrypt_tag))
        if self.decrypt_tag != b'' and self.decrypt_nonce != b'' and self.decrypt_key != b'':
            self.error_tag_decrypt.place_forget()
            self.importkeystag["text"] = "Imported"
            self.importkeysbutton["text"] = "Change Keys"
        else:
            self.error_tag_decrypt["text"] = "Invalid Keys"
            self.error_tag_decrypt.place(rely=0.05, relx=0.5)
        self.getkeyswindow.destroy()

    def resetencryptloggedapp(self):
        self.processlabel.place_forget()
        self.show_keys_button.place_forget()
        self.reset_button.place_forget()
        self.selectdesttag["text"] = "File Destination"
        self.selectfiletag["text"] = "File to Encrypt"
        self.processlabel["text"] = "Encrypting..."
        self.chosen_dest = ""
        self.chosen_file = ""
        self.selectdestinationbutton["text"] = "Choose Destination"
        self.selectfilebutton["text"] = "Import"

    def resetdecryptloggedapp(self):
        self.processlabeldecrypt.place_forget()
        self.reset_button_decrypt.place_forget()
        self.selectdesttagdecrypt["text"] = "File Destination"
        self.selectfiletagdecrypt["text"] = "File to Decrypt"
        self.processlabeldecrypt["text"] = "Encrypting..."
        self.chosen_decrypt_file = ""
        self.chosen_decrypt_dest = ""
        self.selectdestbuttondecrypt["text"] = "Choose Destination"
        self.selectfilebuttondecrypt["text"] = "Import"
        self.importkeystag["text"] = "Import Keys"
        self.importkeysbutton["text"] = "Import"
        self.decrypt_key = ""
        self.decrypt_tag = ""
        self.decrypt_nonce = ""

    def loginconndb(self):
        self.trylogin(self.username_entry.get(), self.psw_entry.get())

    def trylogin(self, username, password):
        self.cur.execute("SELECT uid, psw FROM users WHERE uid = '%s' AND psw = '%s'" % (username, password))
        if self.cur.fetchone():
            self.show_logged_app(username)
        else:
            self.error_login['text'] = "Invalid Login Details"

    def importfile(self):
        self.chosen_file = tkinter.filedialog.askopenfilename(initialdir = self.dir, title = "Choose file to encrypt")
        if self.chosen_file != "":
            self.selectfiletag["text"] = "File to encrypt: %s" % (os.path.basename(self.chosen_file))
            self.selectfilebutton["text"] = "Change File"
            self.error_tag.place_forget()
        else:
            self.error_tag["text"] = "Invalid File"
            self.error_tag.place(rely=0.05, relx=0.6)
            self.chosen_file = ""

    def importdecryptfile(self):
        self.chosen_decrypt_file = tkinter.filedialog.askopenfilename(initialdir = self.dir, title = "Choose file to encrypt")
        if self.chosen_decrypt_file != "" and os.path.splitext(self.chosen_decrypt_file)[1] == ".png":
            self.selectfiletagdecrypt["text"] = "File to Decrypt: %s" % (os.path.basename(self.chosen_decrypt_file))
            self.selectfilebuttondecrypt["text"] = "Change File"
            self.error_tag_decrypt.place_forget()
        else:
            self.error_tag_decrypt["text"] = "Invalid File"
            self.error_tag_decrypt.place(rely=0.05, relx=0.5)
            self.chosen_decrypt_file = ""


    def choosedest(self):
        self.chosen_dest = tkinter.filedialog.askdirectory(initialdir = self.dir, title = "Choose destination")
        if self.chosen_dest != "":
            self.selectdesttag["text"] = "File destination: /%s" % (os.path.basename(self.chosen_dest))
            self.selectdestinationbutton["text"] = "Change Destination"
            self.error_tag.place_forget()
        else:
            self.error_tag["text"] = "Invalid Destination"
            self.error_tag.place(rely=0.05, relx=0.6)
            self.chosen_dest = ""

    def choosedecryptdest(self):
        self.chosen_decrypt_dest = tkinter.filedialog.askdirectory(initialdir = self.dir, title = "Choose destination")
        if self.chosen_decrypt_dest != "":
            self.selectdesttagdecrypt["text"] = "File destination: /%s" % (os.path.basename(self.chosen_decrypt_dest))
            self.selectdestbuttondecrypt["text"] = "Change Destination"
            self.error_tag_decrypt.place_forget()
        else:
            self.error_tag_decrypt["text"] = "Invalid Destination"
            self.error_tag_decrypt.place(rely=0.05, relx=0.5)
            self.chosen_decrypt_dest = ""

    def doencrypt(self):
        #self.encryptbar.place(rely=0.3, relx=0.6)
        #print(self.chosen_file, self.chosen_dest)
        self.error_tag.place_forget()
        if self.chosen_dest == "" or self.chosen_file == "":
            self.error_tag["text"] = "Invalid File or destination"
            self.error_tag.place(rely=0.05, relx=0.6)
        else:
            try:
                self.processlabel.place(rely=0.05, relx=0.6)
                self.root.update_idletasks()
                self.key, self.nonce, self.tag = self.encryption_service.encode(self.chosen_file, self.chosen_dest)
        # encoded_string = self.encryption_service.read_file(self.chosen_file)
        # new_encoded_string, self.key, self.nonce, self.tag = self.encryption_service.encode_AES(encoded_string)
        # val = self.encryption_service.make_hex(new_encoded_string)
        # rgb = self.encryption_service.make_rgb(val)
        # self.encryption_service.create_pic(rgb, self.chosen_file, self.chosen_dest)
                print(self.key, self.nonce, self.tag)
                self.processlabel["text"] = "Complete"
                self.show_keys_button.place(rely=0.3, relx=0.6)
                self.reset_button.place(rely=0.5, relx=0.6)
            except:
                self.processlabel.place_forget()
                self.error_tag["text"] = "Unexpected Error"
                self.error_tag.place(rely=0.05, relx=0.6)

    def dodecrypt(self):
        if self.chosen_decrypt_dest == "" or self.chosen_decrypt_file == "" or os.path.splitext(self.chosen_decrypt_file)[1] != ".png":
            self.error_tag_decrypt["text"] = "Invalid File or destination"
            self.error_tag_decrypt.place(rely=0.05, relx=0.5)
        elif self.decrypt_tag == b'' or self.decrypt_key == b'' or self.decrypt_nonce == b'' or  self.decrypt_tag == "" or self.decrypt_key == "" or self.decrypt_nonce == "":
            self.error_tag_decrypt["text"] = "Invalid Keys"
            self.error_tag_decrypt.place(rely=0.05, relx=0.5)
        else:
            try:
                self.processlabeldecrypt.place(rely=0.05, relx=0.595)
                self.root.update_idletasks()
                self.encryption_service.decode(self.chosen_decrypt_file, self.chosen_decrypt_dest, self.decrypt_key, self.decrypt_nonce, self.decrypt_tag)
                self.processlabeldecrypt["text"] = "Complete"
                self.reset_button_decrypt.place(rely=0.3, relx=0.6)
            except:
                self.processlabeldecrypt.place_forget()
                self.error_tag_decrypt["text"] = "Could not Decrypt"
                self.error_tag_decrypt.place(rely=0.05, relx=0.5)

    def update_bar(self, value):
        self.encryptbar["value"] = value
        self.root.update_idletasks()
        time.sleep(1)

    def hover_logout(self, *args):
        self.logouttag.config(fg="red")

    def exit_hover_logout(self, *args):
        self.logouttag.config(fg="black")

    def hover_return_home(self, *args):
        self.returnhome.config(fg="red")

    def exit_return_home(self, *args):
        self.returnhome.config(fg="black")

class Encryption(mainApp):
    def __init__(self):
        pass

    def encode_AES(self, encoded_string):
        key = os.urandom(32)
        cipher = AES.new(key, AES.MODE_EAX)
        #print("key: " + str(key))
        nonce = cipher.nonce
        #print("nonce: " + str(nonce))
        ciphertext, tag = cipher.encrypt_and_digest(encoded_string)
        #print("tag: " + str(tag))
        #print(ciphertext)

        new_encoded_string = str(base64.b16encode(ciphertext))[2:-1]
        return new_encoded_string, key, nonce, tag

    def make_hex(self, new_encoded_string):
        val = [new_encoded_string[i:i+6] for i in range(0, len(new_encoded_string), 6)]
        #print(val[-3:])
        fix = 6-len(val[-1])
        #print(fix)
        #val[-1] = (val[-1] + (6-len(val[-1]))*"0") if (len(val[-1]) < 6) else val[-1]
        if (len(val[-1]) < 6):
            val[-1] = (val[-1] + (6-len(val[-1]))*"0")
            val.append("00000" + str(fix)) #NUM AT THE END IS HOW MANY 0S WERE ADDED TO PREVIOUS INDEX
        else:
            val.append("00000F") #ADDS F TO SHOW THERE'S NO FIXING
        #print(val[-3:])
        return val

    def make_rgb(self, val):
        rgb = [tuple(int(h[i:i+2], 16) for i in (0, 2, 4)) for h in val]
        #print(rgb[-3:])
        return rgb

    def create_pic(self, rgb, file_loc, path):
        x = y = math.ceil(len(rgb)**(1/2))
        while (x*y) - len(rgb) >= x:  #this is to optimise size, it removes some width to picture as i saw it tended to use excess width - kinda hard but it just saves me some pixels
            x -= 1
        #print(x,y)
        im1 = Image.new("RGB", (x,y))  #here just makes the pic
        im1.putdata(rgb)
        #print(path + os.path.basename(file_loc) + ".png")
        im1.save(path + "/" + os.path.basename(file_loc) + ".png")
        print("******ENCRYPTION COMPLETE******")

    def read_file(self, file_loc):
        with open(file_loc, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        return encoded_string

    def encode(self, file_loc, dest):
        encoded_string = self.read_file(file_loc)
        new_encoded_string, key, nonce, tag = self.encode_AES(encoded_string)
        val = self.make_hex(new_encoded_string)
        rgb = self.make_rgb(val)
        self.create_pic(rgb, file_loc, dest)
        return key, nonce, tag

    def read_image_getpix(self, file_loc):
        imx = Image.open(file_loc)
        pix = imx.load()
        size = imx.size
        values = [pix[x,y] for y in range(size[1]) for x in range(size[0])]
        return values
    
    def get_b16_adjusted(self, values):
        b16 = ["{:02x}{:02x}{:02x}".format(item[0],item[1],item[2]) for item in values]
        #print(b16[:10])
        while b16[-1] == "000000": 
            del b16[-1]
        #print(b16[-1])
        if b16[-1][-1].upper() == "F":
            del b16[-1]
        else:
            fix = int(b16[-1][-1])
            del b16[-1]
            b16[-1] = b16[-1][:-fix]
        b16_decoded_string = base64.b16decode(bytes(''.join(b16).upper(), 'utf-8'))
        return b16_decoded_string

    def decode_AES(self, decoded_string, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher.decrypt(decoded_string)
        try:
            cipher.verify(tag)
            print("The message is authentic")
            return decrypted_data
        except ValueError:
            print("Key incorrect or message corrupted")
            return None
    
    def write_to_file(self, file_loc, dest, decrypted_data):
        filedata = base64.b64decode(decrypted_data)
        with open(dest + "/" + os.path.basename(os.path.splitext(file_loc)[0]), "wb") as f:
            f.write(filedata)
    
    def decode(self, file_loc, dest, key, nonce, tag):
        values = self.read_image_getpix(file_loc)
        b16_decoded_string = self.get_b16_adjusted(values)
        decrypted_data = self.decode_AES(b16_decoded_string, key, nonce, tag)
        self.write_to_file(file_loc, dest, decrypted_data)

app = mainApp()
app.run()
