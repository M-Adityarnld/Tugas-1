import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganografi - Penyisipan dan Deskripsi Gambar")
        self.root.geometry("800x400")
        self.root.configure(bg="#f0f0f0")  # Warna latar belakang

        style = ttk.Style()
        style.theme_use('clam')
        
        # Gaya untuk tombol
        style.configure("TButton", background="#4CAF50", foreground="white", font=("Times New Roman", 10))
        style.map("TButton", background=[('active', '#45a049')])
        
        # Gaya untuk label frame
        style.configure("TLabelFrame", background="#e0e0e0", font=("Times New Roman", 12))
        
        self.create_widgets()

    def create_widgets(self):
        # Tab untuk menyisipkan pesan dan mendeskripsikan gambar
        main_frame = ttk.Frame(self.root)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Frame untuk menyisipkan pesan
        embed_frame = ttk.LabelFrame(main_frame, text="Sisipkan Pesan", padding=(10, 10))
        embed_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.image_label = ttk.Label(embed_frame, text="Belum ada gambar yang dipilih.")
        self.image_label.pack(anchor="w")

        ttk.Button(embed_frame, text="Pilih Gambar untuk Disisipkan", command=self.load_image).pack(pady=5)

        # Frame untuk input teks yang akan disisipkan
        self.embed_text_input = tk.Text(embed_frame, height=10, font=("Times New Roman", 12))
        self.embed_text_input.pack(fill="both", expand=True)

        # Buttons untuk enkripsi
        button_frame = ttk.Frame(embed_frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Sisipkan Teks", command=self.embed_text_in_image).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Bersihkan", command=self.clear_embed_fields).pack(side="left", padx=5)

        # Frame untuk mendeskripsikan gambar
        description_frame = ttk.LabelFrame(main_frame, text="Deskripsi Gambar", padding=(10, 10))
        description_frame.pack(side="right", fill="both", expand=True, padx=5)

        self.description_image_label = ttk.Label(description_frame, text="Belum ada gambar yang dipilih.")
        self.description_image_label.pack(anchor="w")
        
        ttk.Button(description_frame, text="Pilih Gambar untuk Deskripsi", command=self.load_image_for_description).pack(pady=5)

        # Output frame untuk menampilkan pesan yang dideskripsikan
        output_frame = ttk.LabelFrame(description_frame, text="Pesan yang Didapat", padding=(10, 10))
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.extracted_text_output = tk.Text(output_frame, height=10, font=("Times New Roman", 12))
        self.extracted_text_output.pack(fill="both", expand=True)

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=f"Gambar dipilih: {file_path}")
            self.show_image(Image.open(self.image_path), self.image_label)  # Tampilkan gambar yang dipilih

    def load_image_for_description(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if file_path:
            self.description_image_path = file_path
            self.description_image_label.config(text=f"Gambar dipilih: {file_path}")
            self.show_image(Image.open(self.description_image_path), self.description_image_label)  # Tampilkan gambar untuk deskripsi
            # Langsung mendeskripsikan gambar setelah memilihnya
            self.describe_text_from_image()  # Panggil metode deskripsi gambar

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
        img = img.convert("RGBA")  # Mengonversi gambar menjadi RGBA
        img_array = np.array(img)
        binary_message = ''.join(format(ord(char), '08b') for char in message) + '11111111'  # Terminator
        message_index = 0
        
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                pixel = img_array[i, j].tolist()  # Mengonversi array menjadi list
                for n in range(3):  # Hanya modifikasi R, G, B channels
                    if message_index < len(binary_message):
                        pixel[n] = (pixel[n] & ~1) | int(binary_message[message_index])
                        message_index += 1
                img_array[i, j] = tuple(pixel)  # Mengupdate pixel

                if message_index >= len(binary_message):
                    break
        
        return Image.fromarray(img_array.astype(np.uint8), mode="RGBA")  # Pastikan tipe data uint8 dan kembalikan sebagai RGBA

    def lsb_decode(self, img):
        img = img.convert("RGBA")  # Mengonversi gambar menjadi RGBA
        img_array = np.array(img)
        binary_message = ""
        
        # Membaca bit dari setiap pixel
        for i in range(img_array.shape[0]):
            for j in range(img_array.shape[1]):
                pixel = img_array[i, j]
                for n in range(3):  # Membaca R, G, B channels
                    binary_message += str(pixel[n] & 1)

        # Split into bytes and decode
        message_bytes = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
        message = ''
        
        for byte in message_bytes:
            char_code = int(byte, 2)
            if byte == '11111111':  # Jika byte adalah 255, itu berarti pesan telah selesai
                break
            if char_code == 0:
                continue  # Abaikan byte nol
            message += chr(char_code)
        
        return message.strip()  # Kembalikan pesan yang sudah dibersihkan dari spasi

    def clear_embed_fields(self):
        self.embed_text_input.delete("1.0", tk.END)
        self.image_label.config(text="Belum ada gambar yang dipilih.")

    def show_image(self, img, label):
        img.thumbnail((150, 150))  # Mengubah ukuran gambar agar lebih kecil
        img_tk = ImageTk.PhotoImage(img)
        label.config(image=img_tk)
        label.image = img_tk  # Simpan referensi gambar

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
