from tkinter import *
from Crypto.Cipher import DES3,AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
import base64
from tkinter import messagebox
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted = base64.b64encode(encrypted_message).decode('utf-8')
    return iv, encrypted
def decrypt_message(key, iv, encrypted_message):
    cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv.encode('utf-8')))
    decrypted_message = unpad(cipher.decrypt(base64.b64decode(encrypted_message.encode('utf-8'))), AES.block_size)
    return decrypted_message.decode()

def AESencrypt():
    key = key_entry.get().encode()
    message = plaintext_entry.get()
    iv, encrypted = encrypt_message(key, message)
    iv_entry.delete(0, END)
    iv_entry.insert(END, iv)
    ciphertext_entry.delete(0, END)
    ciphertext_entry.insert(END, encrypted)

def AESdecrypt():
    key = key_entry.get().encode()
    iv = iv_entry.get()
    encrypted = ciphertext_entry.get()
    decrypted = decrypt_message(key, iv, encrypted)
    decrypted_entry.delete(0, END)
    decrypted_entry.insert(END, decrypted)









#des3 algorithm functions
def encrypt_dataDes3():
    key = key_entry.get().encode('utf-8')
    plaintext = plaintext_entry.get().encode('utf-8')
    if len(key) != 24:
        messagebox.showerror("Error", "Invalid key length. Key must be 24 bytes.")
        return
    try:

        cipher = DES3.new(key, DES3.MODE_ECB)
        padded_plaintext = pad(plaintext, DES3.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        ciphertext_entry.delete(0, tk.END)
        ciphertext_entry.insert(0, ciphertext.hex())
    except ValueError as e:
        messagebox.showerror("Error", str(e))
def decrypt_dataDes3():
    key = key_entry.get().encode('utf-8')
    ciphertext_hex = ciphertext_entry.get()
    if len(key) != 24:
        messagebox.showerror("Error", "Invalid key length. Key must be 24 bytes.")
        return
    try:
        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = bytes.fromhex(ciphertext_hex)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, DES3.block_size)
        decrypted_entry.delete(0, tk.END)
        decrypted_entry.insert(0, plaintext.decode('utf-8'))
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()

    ciphertext = ''
    for i in range(len(plaintext)):
        ciphertext += chr((ord(plaintext[i]) ^ ord(key[i])) % 95 + 32)
    ciphertext_entry.delete("0", END)
    ciphertext_entry.insert(END, ciphertext)

def decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    plaintext = ''
    for i in range(len(ciphertext)):
        plaintext += chr((ord(ciphertext[i]) ^ ord(key[i])) % 95+32)
    decrypted_entry.delete("0", END)
    decrypted_entry.insert(END, plaintext)



root = Tk()
root.title("One-Time Pad Encryption")
plaintext_label = Label(root, text="Plaintext:")
plaintext_label.grid(row=0, column=0, padx=5, pady=5)
plaintext_entry = Entry(root)
plaintext =plaintext_entry.get()


plaintext_entry.grid(row=0, column=1, padx=5, pady=5)
key_label = Label(root, text="Key:")
key_label.grid(row=1, column=0, padx=5, pady=5)
key_entry = Entry(root,show="x")
key_entry.grid(row=1, column=1, padx=5, pady=5)
key = key_entry.get()
ciphertext_label = Label(root, text="Ciphertext:")
ciphertext_label.grid(row=2, column=0, padx=5, pady=5)
ciphertext_entry = Entry(root)
ciphertext_entry.grid(row=2, column=1, padx=5, pady=5)
ciphertext_label = Label(root, text="decrptedtext:")
ciphertext_label.grid(row=2, column=2, padx=5, pady=5)
decrypted_entry = Entry(root)
decrypted_entry.grid(row=2, column=3, padx=5, pady=5)
lable2=Label(root,text='iV:')
lable2.grid(row=3,column=2)
iv_entry = Entry(root)
iv_entry.grid(row=3, column=3, padx=90, pady=10)
encrypt_button = Button(root, text="OTPEncrypt", command=encrypt)
encrypt_button.grid(row=3, column=0, padx=5, pady=5)
decrypt_button = Button(root, text="OTPDecrypt", command=decrypt)
decrypt_button.grid(row=3, column=1, padx=5, pady=5)

encrypt_button = Button(root, text="desEncrypt", command=encrypt_dataDes3)
encrypt_button.grid(row=10, column=0, padx=5, pady=5)
decrypt_button = Button(root, text="desDecrypt", command=decrypt_dataDes3)
decrypt_button.grid(row=10, column=1, padx=5, pady=5)

encrypt_button = Button(root, text="AesEncrypt", command=AESencrypt).grid(row=20, column=0, padx=5, pady=5)
decrypt_button = Button(root, text="AesDecrypt", command=AESdecrypt).grid(row=20, column=1, padx=5, pady=5)
#COMBOBOX
option=['otp','des3','AES']

root.mainloop()


