from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import messagebox

def encrypt_data():
    key = key_entry.get().encode('utf-8')
    plaintext = plaintext_entry.get().encode('utf-8')
    if len(key) != 24:
        messagebox.showerror("Error", "Invalid key length. Key must be 24 bytes.")
        return
    try:
        # Initialize TDES cipher object with key and mode
        cipher = DES3.new(key, DES3.MODE_ECB)
        # Pad the plaintext to a multiple of the block size
        padded_plaintext = pad(plaintext, DES3.block_size)
        # Encrypt the padded plaintext
        ciphertext = cipher.encrypt(padded_plaintext)
        # Convert the ciphertext to a hexadecimal string and set it in the result entry widget
        result_entry.delete(0, tk.END)
        result_entry.insert(0, ciphertext.hex())
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def decrypt_data():
    key = key_entry.get().encode('utf-8')
    ciphertext_hex = result_entry.get()
    if len(key) != 24:
        messagebox.showerror("Error", "Invalid key length. Key must be 24 bytes.")
        return
    try:
        # Initialize TDES cipher object with key and mode
        cipher = DES3.new(key, DES3.MODE_ECB)
        # Convert the ciphertext from hexadecimal string to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)
        # Decrypt the ciphertext
        padded_plaintext = cipher.decrypt(ciphertext)
        # Unpad the plaintext
        plaintext = unpad(padded_plaintext, DES3.block_size)
        # Set the plaintext in the plaintext entry widget
        plaintext_entry.delete(0, tk.END)
        plaintext_entry.insert(0, plaintext.decode('utf-8'))
    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Initialize Tkinter GUI
root = tk.Tk()
root.title("TDES Encryption/Decryption")

# Create GUI elements
key_label = tk.Label(root, text="Key:")
key_entry = tk.Entry(root)
plaintext_label = tk.Label(root, text="Plaintext:")
plaintext_entry = tk.Entry(root)
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_data)
result_label = tk.Label(root, text="Result:")
result_entry = tk.Entry(root)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_data)

# Place GUI elements on the grid
key_label.grid(row=0, column=0)
key_entry.grid(row=0, column=1)
plaintext_label.grid(row=1, column=0)
plaintext_entry.grid(row=1, column=1)
encrypt_button.grid(row=2, column=0, columnspan=2, pady=10)
result_label.grid(row=3, column=0)
result_entry.grid(row=3, column=1)
decrypt_button.grid(row=4, column=0, columnspan=2, pady=10)



# Start the Tkinter event loop
root.mainloop()

