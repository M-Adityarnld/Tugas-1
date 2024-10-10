import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
from PIL import Image, ImageTk
import numpy as np

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

# --------------------------- STEGANOGRAPHY ---------------------------
class SteganographyApp:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        # Frame for embedding message
        embed_frame = ttk.LabelFrame(self.frame, text="Sisipkan Pesan", padding=(10, 10))
        embed_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.image_label = ttk.Label(embed_frame, text="Belum ada gambar yang dipilih.")
        self.image_label.pack(anchor="w")

        self.image_display = ttk.Label(embed_frame)  # Label to display the selected image
        self.image_display.pack(pady=5)

        ttk.Button(embed_frame, text="Pilih Gambar untuk Disisipkan", command=self.load_image).pack(pady=5)

        self.embed_text_input = tk.Text(embed_frame, height=10, font=("Times New Roman", 12))
        self.embed_text_input.pack(fill="both", expand=True)

        button_frame = ttk.Frame(embed_frame)
        button_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(button_frame, text="Sisipkan Teks", command=self.embed_text_in_image).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Bersihkan", command=self.clear_embed_fields).pack(side="left", padx=5)

        # Frame for describing image
        description_frame = ttk.LabelFrame(self.frame, text="Deskripsi Gambar", padding=(10, 10))
        description_frame.pack(side="right", fill="both", expand=True, padx=5)

        self.description_image_label = ttk.Label(description_frame, text="Belum ada gambar yang dipilih.")
        self.description_image_label.pack(anchor="w")

        self.description_image_display = ttk.Label(description_frame)  # Label to display the selected image
        self.description_image_display.pack(pady=5)

        ttk.Button(description_frame, text="Pilih Gambar untuk Deskripsi", command=self.load_image_for_description).pack(pady=5)

        output_frame = ttk.LabelFrame(description_frame, text="Pesan yang Didapat", padding=(10, 10))
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.extracted_text_output = tk.Text(output_frame, height=10, font=("Times New Roman", 12))
        self.extracted_text_output.pack(fill="both", expand=True)

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=f"Gambar dipilih: {file_path}")
            self.display_image(file_path, self.image_display)  # Display the selected image

    def load_image_for_description(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.description_image_path = file_path
            self.description_image_label.config(text=f"Gambar dipilih: {file_path}")
            self.display_image(file_path, self.description_image_display)  # Display the selected image
            self.describe_text_from_image()

    def display_image(self, image_path, label):
        # Open the image and resize it for display
        img = Image.open(image_path)
        img.thumbnail((200, 200))  # Resize the image to fit in the label
        self.photo = ImageTk.PhotoImage(img)  # Keep a reference to avoid garbage collection
        label.config(image=self.photo)  # Update the label with the new image
        label.image = self.photo  # Keep a reference to avoid garbage collection

    def embed_text_in_image(self):
        if not hasattr(self, 'image_path'):
            messagebox.showwarning("Peringatan", "Silakan pilih gambar terlebih dahulu")
            return

        message = self.embed_text_input.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Peringatan", "Silakan masukkan teks untuk disisipkan")
            return

        try:
            img = Image.open(self.image_path)
            encoded_img = self.lsb_encode(img, message)
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if save_path:
                encoded_img.save(save_path)
                messagebox.showinfo("Berhasil", f"Teks berhasil disisipkan ke gambar: {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyisipkan teks: {str(e)}")

    def describe_text_from_image(self):
        if not hasattr(self, 'description_image_path'):
            messagebox.showwarning("Peringatan", "Silakan pilih gambar terlebih dahulu")
            return

        try:
            img = Image.open(self.description_image_path)
            extracted_message = self.lsb_decode(img)
            self.extracted_text_output.delete("1.0", tk.END)
            if extracted_message:
                self.extracted_text_output.insert("1.0", extracted_message)
            else:
                self.extracted_text_output.insert("1.0", "Tidak ada pesan yang ditemukan.")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal mendeskripsikan gambar: {str(e)}")

    def lsb_encode(self, img, message):
        img = img.convert("RGBA")
        img_array = np.array(img)
        binary_message = ''.join(format(ord(char), '08b') for char in message) + '11111111'
        message_index = 0

        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                pixel = img_array[i, j].tolist()
                for n in range(3):
                    if message_index < len(binary_message):
                        pixel[n] = (pixel[n] & ~1) | int(binary_message[message_index])
                        message_index += 1
                img_array[i, j] = tuple(pixel)

                if message_index >= len(binary_message):
                    break

        return Image.fromarray(img_array.astype(np.uint8), mode="RGBA")

    def lsb_decode(self, img):
        img = img.convert("RGBA")
        img_array = np.array(img)
        binary_message = ""

        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                pixel = img_array[i, j]
                for n in range(3):
                    binary_message += str(pixel[n] & 1)

        message_bytes = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
        message = ''
        
        for byte in message_bytes:
            char_code = int(byte, 2)
            if byte == '11111111':
                break
            if char_code == 0:
                continue
            message += chr(char_code)

        return message.strip()

    def clear_embed_fields(self):
        self.embed_text_input.delete("1.0", tk.END)
        self.image_label.config(text="Belum ada gambar yang dipilih.")

# --------------------------- CRYPTOGRAPHY ---------------------------
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
        self.frame = ttk.Frame(root)
        self.frame.pack(fill="both", expand=True)
        self.var_algorithm = tk.StringVar(value="AES")
        self.key = get_random_bytes(16)
        
        # Labels and Entries
        tk.Label(self.frame, text="Select Algorithm").pack(pady=10)
        self.aes_radio = tk.Radiobutton(self.frame, text="AES", variable=self.var_algorithm, value="AES")
        self.rsa_radio = tk.Radiobutton(self.frame, text="RSA", variable=self.var_algorithm, value="RSA")
        self.aes_radio.pack()
        self.rsa_radio.pack()

        self.text_label = tk.Label(self.frame, text="Enter Text")
        self.text_label.pack(pady=10)
        self.text_entry = tk.Entry(self.frame, width=60)
        self.text_entry.pack()

        self.result_label = tk.Label(self.frame, text="Result")
        self.result_label.pack(pady=10)
        self.result_entry = tk.Entry(self.frame, width=60)
        self.result_entry.pack()

        self.encrypt_button = tk.Button(self.frame, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.pack(pady=10)
        self.decrypt_button = tk.Button(self.frame, text="Decrypt", command=self.decrypt_text)
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


# --------------------------- MAIN APPLICATION ---------------------------
class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Message Program")
        self.root.geometry("900x500")

        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        # Create separate frames for each tab
        self.crypto_app = CryptoApp(self.notebook)
        self.steganography_app = SteganographyApp(self.notebook)

        # Add tabs
        self.notebook.add(self.crypto_app.frame, text="Cryptography")
        self.notebook.add(self.steganography_app.frame, text="Steganography")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()
