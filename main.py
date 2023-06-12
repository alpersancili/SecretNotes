import tkinter
from tkinter import messagebox
from PIL import ImageTk,Image
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=350,height=600)
FONT = ("Arial",13,"normal")

image = Image.open("decryption.png")
new_image = image.resize((100,100))
my_image = ImageTk.PhotoImage(new_image)
my_label = tkinter.Label(image=my_image)
my_label.place(x=125,y=50)

title_label = tkinter.Label(text="Enter your title",font=FONT)
title_label.place(x=120,y=170)

title_input = tkinter.Entry(width=35)
title_input.place(x=70,y=200)

secret_label = tkinter.Label(text="Enter your secret",font=FONT)
secret_label.place(x=110,y=225)

secret_input = tkinter.Text(height=12,width=30)
secret_input.place(x=53,y=250)

key_label = tkinter.Label(text="Enter master key",font=FONT)
key_label.place(x=110,y=435)

key_input = tkinter.Entry(width=35)
key_input.place(x=65,y=460)

def save_encrypt():
    title = title_input.get()
    message = secret_input.get("1.0",'end-1c')
    master_secret = key_input.get()

    if len(title) == 0 and len(message) == 0 and len(master_secret) == 0:
        messagebox.showinfo("Error!",message="Please enter all info")
    else:
        try:
            with open(r"C:\Users\alper\PycharmProjects\SecretNotes\secret.txt","r") as f:
                f.read()
        except:
            with open(r"C:\Users\alper\PycharmProjects\SecretNotes\secret.txt", "w") as f:
                f.write(title_input.get())
                f.write("\n")
                message_encrypted = encode(master_secret,message)
                f.write(message_encrypted)
                title_input.delete(0,"end")
                secret_input.delete("1.0",'end-1c')
                key_input.delete(0,"end")

def show_decrypt():
    message_encrypted = secret_input.get("1.0", 'end-1c')
    master_secret = key_input.get()

    if len(message_encrypted) == 0 and len(master_secret) == 0:
        messagebox.showinfo("Error!",message="Please enter all info")
    else:
        try:
            message_decrypted = decode(master_secret,message_encrypted)
            secret_input.delete("1.0",'end-1c')
            secret_input.insert("1.0",message_decrypted)
        except:
            messagebox.showinfo("Error!", message="Please enter encrypted text")

encrypt_button = tkinter.Button(text="Save & Encrypt",width=13,command=save_encrypt)
encrypt_button.place(x=120,y=485)

decrypt_button = tkinter.Button(text="Decrypt",width=13,command=show_decrypt)
decrypt_button.place(x=120,y=520)



window.mainloop()