import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# --------------------------- AES ENCRYPTION/DECRYPTION ---------------------------
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# --------------------------- RSA ENCRYPTION/DECRYPTION ---------------------------
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# --------------------------- GUI DESIGN ---------------------------
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography App")
        self.root.geometry("600x500")
        self.root.configure(bg="lightblue")

        self.var_algorithm = tk.StringVar(value="AES")
        self.key = get_random_bytes(16)

        # Labels and Entries
        tk.Label(root, text="Select Algorithm", bg="lightblue").pack(pady=10)
        self.aes_radio = tk.Radiobutton(root, text="AES", variable=self.var_algorithm, value="AES", bg="lightblue")
        self.rsa_radio = tk.Radiobutton(root, text="RSA", variable=self.var_algorithm, value="RSA", bg="lightblue")
        self.aes_radio.pack()
        self.rsa_radio.pack()

        self.text_label = tk.Label(root, text="Enter Text", bg="lightblue")
        self.text_label.pack(pady=10)
        self.text_entry = tk.Entry(root, width=60)  # Field size updated to be longer
        self.text_entry.pack()

        self.result_label = tk.Label(root, text="Result", bg="lightblue")
        self.result_label.pack(pady=10)
        self.result_entry = tk.Entry(root, width=60)  # Field size updated to be longer
        self.result_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_text, bg="green", fg="white")
        self.encrypt_button.pack(pady=10)
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_text, bg="red", fg="white")
        self.decrypt_button.pack(pady=10)

        self.private_key, self.public_key = rsa_generate_keys()

    def encrypt_text(self):
        text = self.text_entry.get()
        algorithm = self.var_algorithm.get()
        
        if algorithm == "AES":
            ciphertext = aes_encrypt(text, self.key)
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, ciphertext)
        elif algorithm == "RSA":
            ciphertext = rsa_encrypt(text, self.public_key)
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, ciphertext)
        else:
            messagebox.showerror("Error", "Unknown algorithm")

    def decrypt_text(self):
        # Ambil cipher text dari input text
        ciphertext = self.text_entry.get()
        algorithm = self.var_algorithm.get()

        try:
            if algorithm == "AES":
                plaintext = aes_decrypt(ciphertext, self.key)
                self.result_entry.delete(0, tk.END)
                self.result_entry.insert(0, plaintext)
            elif algorithm == "RSA":
                plaintext = rsa_decrypt(ciphertext, self.private_key)
                self.result_entry.delete(0, tk.END)
                self.result_entry.insert(0, plaintext)
            else:
                messagebox.showerror("Error", "Unknown algorithm")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# Running the App
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
