import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import secrets
import string

backend = default_backend()
salt = b"2444"

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt = salt,
    iterations=100000,
    backend = backend,
)

encryptionKey = 0

def encrypt(message: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8'))

def decrypt (message: bytes, token: bytes) -> str:
    f = Fernet(token)
    return f.decrypt(message).decode('utf-8')


def genPassword(length: int) -> str:
    return "".join(
    (secrets.choice(string.ascii_letters + string.digits + string.punctuation)
        for i in range(length)
            )
        )

with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL
);  
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterkey(
id INTEGER PRIMARY KEY,
masterKeyPassword TEXT NOT NULL,
masterKeyRecoveryKey TEXT NOT NULL);
""")

def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

window = Tk()
window.update()

window.title("Password Vault")

def hashPassword(input_data):
    hash1 = hashlib.sha256(input_data)
    hash1 = hash1.hexdigest()
    return hash1

def firstTimeScreen(hasMasterKey=None):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode())
            key = str(uuid.uuid4().hex)
            hashedRecoveryKey = hashPassword(key.encode())


            insert_password = """INSERT INTO masterpassword(hashedPassword, hashedRecoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (hashedRecoveryKey)))


            masterKey = hasMasterKey if hasMasterKey else genPassword(64)
            cursor.execute("SELECT * FROM masterkey")
            if cursor.fetchall():
                cursor.execute("DELETE FROM masterpassword WHERE id = 1")

            insert_masterkey = """ INSERT INTO masterkey(masterKeyPassword, masterKeyRecoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_masterkey,(
                    encrypt(masterKey, base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))),
                    encrypt(key, base64.urlsafe_b64encode(kdf.derive(key.encode()))),
            ))


            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            db.commit()

            recoveryScreen(key)
        else:
            lbl.configure(text="Password do not match!")

    # Create the button outside the savePassword function
    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    lbl = Label(window, text="Save this key to be able to recovery account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        pyperclip.copy(lbl1.cget("text"))

    btn = Button(window, text="Copy", command=copyKey)
    btn.pack(pady=5)

    def done():
        passwordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=5)

    def resetScreen():
        global txt, lbl1

        for widget in window.winfo_children():
            widget.destroy()

        window.geometry("250x150")
        lbl = Label(window, text="Enter Recovery Key")
        lbl.config(anchor=CENTER)
        lbl.pack()

        txt = Entry(window, width=20)
        txt.pack()
        txt.focus()

        lbl1 = Label(window)
        lbl1.config(anchor=CENTER)
        lbl1.pack()

        btn = Button(window, text="Check Key", command=checkRecoveryKey)
        btn.pack(pady=5)

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode())
        cursor.execute('SELECT *  FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            cursor.execute("Select * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            if masterKeyEntry:
                masterKeyRecoveryKey = masterKeyEntry[0][2]
                masterKey = decrypt(
                    masterKeyRecoveryKey,
                    base64.urlsafe_b64decode(kdf.derive(txt.get().encode()))
                )
                firstTimeScreen(masterKey)
            else:
                print("Master Key not found.")
                exit()
        else:
            txt.delete(0, END)
            lbl1.configure(text="Wrong Password!.")

    btn = Button(window, text="Check Key ", command=checkRecoveryKey)
    btn.pack(pady=5)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x100")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode())

        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(checkHashedPassword)])
        return cursor.fetchall()


    def checkPassword():
        match = getMasterPassword()

        if match:
            cursor.execute("SELECT * FROM masterkey")
            masterKeyEntry = cursor.fetchall()
            if masterKeyEntry:
                masterKeyPassword = masterKeyEntry[0][1]

                print(txt.get().encode())

                masterKey = decrypt(masterKeyPassword,base64.urlsafe_b64encode(kdf.derive(txt.get().encode())))

                global encryptionKey
                encryptionKey = base64.urlsafe_b64encode(kdf.derive(masterKey))

                passwordVault()
            else:
                print("Master Key not found.")
                exit()
        else:
            txt.delete(0, END)
            lbl1.configure(text="Wrong Password!.")

    def resetPassword():
        resetPassword()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=5)

def passwordVault():
    for widget in window.winfo_children():
        widget.destroy()

        def addEntry():
            text1= "Website"
            text2= "Username"
            text3= "Password"
            website = encrypt(popUp(text1), encryptionKey)
            username = encrypt(popUp(text2), encryptionKey)
            password = encrypt(popUp(text3), encryptionKey)


            insert_fields = """INSERT INTO vault(website, username, password)
            VALUES(?, ?, ?)"""
            cursor.execute(insert_fields, (website, username, password))
            db.commit()

            passwordVault()

        def removeEntry(input_id):
            cursor.execute("DELETE FROM vault WHERE id = ?",(input_id,))
            db.commit()

            passwordVault()


    window.geometry("700x350")
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=3, padx=80)

    cursor.execute("SELECT * FROM vault")
    if(cursor.fetchall() != None):
        i = 0
        cursor.execute("SELECT * FROM vault")
        array = cursor.fetchall()
        for i, entry in enumerate(array):
            website = decrypt(entry[1], encryptionKey)
            username = decrypt(entry[2], encryptionKey)
            password = decrypt(entry[3], encryptionKey)

            Label(window, text=website, font=("Arial", 12)).grid(column=0, row=i + 3)
            Label(window, text=username, font=("Arial", 12)).grid(column=1, row=i + 3)
            Label(window, text=password, font=("Arial", 12)).grid(column=2, row=i + 3)

            Button(window, text="Delete", command=partial(removeEntry, entry[0])).grid(column=3, row=i + 3, pady=10)

            i += 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute("SELECT * FROM masterpassword ")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()
