import tkinter as tk
from tkinter import ttk
from tkinter import *
import base64
import ctypes
import tkinter.font as font
import sys
from itertools import cycle
import os
import html
import urllib.parse
import string
import random
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter.filedialog import askopenfilename
from tkinter import simpledialog
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import hashlib

ctypes.windll.shcore.SetProcessDpiAwareness(1)

win = ttk.Window(themename="superhero")
win.geometry("1500x600")
win.title("Encrypter")
font1=('Arial',10,'normal')
  
######menu


    
def about():
    newWindow = Toplevel(win)
    newWindow.title("About Ciphers")
    win.geometry("1500x1000")
    msg00 = ttk.Label(newWindow, text='1. Caesar Cipher: The Caesar cipher is one of the earliest known and simplest ciphers. It is a type of substitution cipher in which each letter in the plaintext is "shifted" a certain number of places down the alphabet.', bootstyle=INFO)
    msg00.grid(row=1,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg01 = ttk.Label(newWindow, text='2. XOR Encryption: The XOR encryption algorithm is an example of symmetric encryption where the same key is used to both encrypt and decrypt a message.', bootstyle=INFO)
    msg01.grid(row=5,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg02 = ttk.Label(newWindow, text='3. Rot13 Encryption: ROT13 ("rotate by 13 places") is a simple letter substitution cipher that replaces a letter with the 13th letter after it in the alphabet.', bootstyle=INFO)
    msg02.grid(row=10,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg03 = ttk.Label(newWindow, text='4. Base64 Encoding: The base64 is a binary to a text encoding scheme that represents binary data in an ASCII string format.', bootstyle=INFO)
    msg03.grid(row=15,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg04 = ttk.Label(newWindow, text='5. HTML Encoding: It is used in order for web browsers to parse non-ASCII special characters in HTML documents with the standard form.', bootstyle=INFO)
    msg04.grid(row=20,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg05 = ttk.Label(newWindow, text='6. URL Encoding: It is a mechanism for translating unprintable or special characters to a universally accepted format by web servers and browsers.', bootstyle=INFO)
    msg05.grid(row=25,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg06 = ttk.Label(newWindow, text='7. RSA Encryption: The RSA encryption algorithm is an asymmetric encryption algorithm that is widely used in many products and services. Asymmetric encryption uses a key pair that is mathematically linked to encrypt and decrypt data.', bootstyle=INFO)
    msg06.grid(row=30,column=1,padx=5,pady=5,columnspan=1, sticky=W)
    msg07 = ttk.Label(newWindow, text='A private and public key are created, with the public key being accessible to anyone and the private key being a secret known only by the key pair creator.', bootstyle=INFO)
    msg07.grid(row=31,column=1,padx=5,pady=5,columnspan=1, sticky=W)

  
menubar = Menu(win, background='#ff8000', foreground='black', activebackground='white', activeforeground='black')
file = Menu(menubar, tearoff=1, background='#ffcc99', foreground='black')

help = Menu(menubar, tearoff=0)  
help.add_command(label="About", command=about)  
menubar.add_cascade(label="Help", menu=help)  

sel=ttk.StringVar() # string variable 

msg0 = ttk.Label(win, text='Please select from the below options:', bootstyle=INFO)
msg0.grid(row=1,column=100,padx=5,pady=5,columnspan=300)
my_opts=['Caesar Cipher','XOR Encryption','Rot13','Base64','HTML Encoding','URL Encoding','RSA Encryption'] # options
cb1 = ttk.Combobox(win, values=my_opts,width=10,height=10,
        textvariable=sel,font=font1, bootstyle=DANGER)
cb1.grid(row=5,column=100,padx=5,pady=5,columnspan=3) 

def my_upd(*args):
    for w in win.grid_slaves(2): 
        w.grid_remove() 
    
    if(sel.get()=='Base64'):
        #base64 logic (Using base64 python library)
      outmsg = StringVar()
      user_choice = IntVar() 
      def base_encrypt(user_text):
        msg = ""
        msg = user_text
        message = msg
        message_bytese = message.encode('ascii')
        base64_bytese = base64.b64encode(message_bytese) 
        base64_messagee = base64_bytese 
        outmsg.set(base64_messagee)
        
      def base_decrypt(user_text):
        msg = ""
        msg = user_text
        message = msg
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')            
        base64_message_decoded = base64.b64decode(base64_message).decode('ascii')
        outmsg.set(base64_message_decoded)
        
      def con():
        user_text = (user_input_text.get())
        text1 = user_text
        text1 = str(text1)
        choice = user_choice.get()
      
        if choice == 0:
          base_encrypt(text1)
        else:
          base_decrypt(text1)
      
      #gui items
      ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
          relx=0.75, rely=0.4, anchor=CENTER)
      ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
          relx=0.9, rely=0.4, anchor=CENTER)
      
      msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
      msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
      msg2 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
      msg2.place(relx=0.5, rely=0.65, anchor=CENTER)
      user_input_text = Entry(win)
      user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
      user_input_text.focus_set()
      stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
      stop.place(relx=0.10, rely=1, anchor=SE)
      
      
      out = Entry(win, text=outmsg).place(
          relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
      
      convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
      convert.place(relx=0.5, rely=0.4, anchor=CENTER)
    #html encoding logic  (Using html python library)
    elif(sel.get()=='HTML Encoding'):
        outmsg = StringVar()
        user_choice = IntVar() 
        def html_encrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          html_bytes = html.escape(message)  #encoding
          outmsg.set(html_bytes)
        def html_decrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          html_bytes_d = html.unescape(message)  #decoding
          outmsg.set(html_bytes_d)
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          choice = user_choice.get()
          
          if choice == 0:
            html_encrypt(text1)
          else:
            html_decrypt(text1)
              #gui items
    
        ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
        msg2.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)
        
    #xor logic
    elif(sel.get()=='XOR Encryption'): #ref: https://github.com/PacktPublishing/Python-for-Offensive-PenTest
        outmsg = StringVar()
        user_choice = IntVar() 
        def xor_encrypt(user_text, user_key):
          alph = ("abcdefghijklmnopqrstuvwxyz")
          msg = ""
          msg = user_text
          message = msg
          strKey = user_key
          xor_enc = ''.join(chr(ord(c)^ord(k)) for c,k in zip(message, cycle(strKey)))
          outmsg.set(xor_enc)
        def xor_decrypt(user_text, user_key):
          alph = ("abcdefghijklmnopqrstuvwxyz")
          msg = ""
          msg = user_text
          message = msg
          strKey = user_key
          xor_dec = ''.join(chr(ord(c)^ord(k)) for c,k in zip(message, cycle(strKey)))
          outmsg.set(xor_dec)
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          user_key = (user_input_key.get())
          key1 = user_key
          key1 = str(key1)
          choice = user_choice.get()
          
          if choice == 0:
            xor_encrypt(text1, user_key)
          else:
            xor_decrypt(text1, user_key)
              #gui items
    
        ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Key', bootstyle=WARNING)
        msg2.place(relx=0.9, rely=0.05, anchor=CENTER)
        user_input_key = Entry(win)
        user_input_key.place(relx=0.9, rely=0.15, anchor=CENTER, width=50, height=50)
        user_input_key.focus_set()
        
        
        msg3 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
        msg3.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)    
        
    #rot13 logic
    elif(sel.get()=='Rot13'): #ref: https://alankrantas.medium.com/several-ways-to-use-rot13-letter-substitution-cipher-in-python-3-d2f438edf1bf
        outmsg = StringVar()
        user_choice = IntVar() 
        def rot_encrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          small = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
          crypalph = []
          ROT13 = 13
          for x in range(0,26):
            crypalph.append(small[(x+ROT13)%26])
          cryptmessage =''
          for x in msg:
              if small.count(x):
                cryptmessage += crypalph[small.index(x.lower())]
              else:
                cryptmessage += x
          rot_bytes = cryptmessage
          outmsg.set(rot_bytes)
          
        def rot_decrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          small = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
          crypalph = []
          ROT13 = 13
          for x in range(0,26):
            crypalph.append(small[(x+ROT13)%26])
          cryptmessage =''
          for x in msg:
              if small.count(x):
                cryptmessage += crypalph[small.index(x.lower())]
              else:
                cryptmessage += x
          decodedmessage =''
          for x in cryptmessage:
            if small.count(x):
              decodedmessage += crypalph[small.index(x.lower())]
            else:
              decodedmessage += x
          rot_bytes = decodedmessage  #encoding
          outmsg.set(rot_bytes)
          
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          choice = user_choice.get()
        
          if choice == 0:
            rot_encrypt(text1)
          else:
            rot_decrypt(text1)
        
        #gui items
        ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
        msg2.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)
        
        #url encoding logic  (Using url python library)
    elif(sel.get()=='URL Encoding'):
        outmsg = StringVar()
        user_choice = IntVar() 
        def url_encrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          message_bytes = message.encode('ascii')
          url_bytes = urllib.parse.quote(message_bytes)
          outmsg.set(url_bytes)
        def url_decrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
          message_bytes = message.encode('ascii')
          url_bytes = urllib.parse.unquote(message_bytes)
          outmsg.set(url_bytes)
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          choice = user_choice.get()
          
          if choice == 0:
            url_encrypt(text1)
          else:
            url_decrypt(text1)
              #gui items
    
        ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
        msg2.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)    

    #caesar cipher logic (ref: https://www.daniweb.com/programming/software-development/threads/333480/python-caesar-cipher-rot13-problem)
    elif(sel.get()=='Caesar Cipher'):
        outmsg = StringVar()
        user_choice = IntVar() 
        def c_encrypt(user_text, user_key):
          alph = string.ascii_lowercase
          msg = ""
          msg = user_text
          message = msg
          strKey = user_key
          key = int(strKey)
          newMsg = ""
          for char in msg:
        	    if char in alph:
        		    pos = alph.find(char)
        		    newPos = (pos + key) % len(alph)
        		    newChar = alph[newPos]
        		    newMsg += newChar
        	    else:
        		    newMsg += char
          outmsg.set(newMsg)
        def c_decrypt(user_text, user_key):
          alph = string.ascii_lowercase
          msg = ""
          msg = user_text
          message = msg
          strKey = user_key
          key = int(strKey)
          newMsg = ""
          for char in msg:
        	    if char in alph:
        		    pos = alph.find(char)
        		    newPos = (pos - key) % len(alph)
        		    newChar = alph[newPos]
        		    newMsg += newChar
        	    else:
        		    newMsg += char
          outmsg.set(newMsg)
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          user_key = (user_input_key.get())
          key1 = user_key
          key1 = str(key1)
          choice = user_choice.get()
          
          if choice == 0:
            c_encrypt(text1, user_key)
          else:
            c_decrypt(text1, user_key)
              #gui items
    
        ttk.Radiobutton(win, text="Encode", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decode", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encode/Decode', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Key', bootstyle=WARNING)
        msg2.place(relx=0.9, rely=0.05, anchor=CENTER)
        user_input_key = Entry(win)
        user_input_key.place(relx=0.9, rely=0.15, anchor=CENTER, width=50, height=50)
        user_input_key.focus_set()
        
        
        msg3 = ttk.Label(win, text='Your Encoded/Decoded string is: ', bootstyle=PRIMARY)
        msg3.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)        
        

        #RSA encryption logic  
    elif(sel.get()=='RSA Encryption'):
        outmsg = StringVar()
        user_choice = IntVar() 
        def rsa_encrypt(user_text):
          msg = ""
          msg = user_text
          #msg = b'user_text'
          msg = bytes(msg, encoding='utf-8')
          keyPair = RSA.generate(3072)

          pubKey = keyPair.publickey()
          print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
          pubKeyPEM = pubKey.exportKey()
          with open("public key.pem", "w") as o:
              o.write(pubKeyPEM.decode('ascii'))
          
          print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
          privKeyPEM = keyPair.exportKey()
          with open("private key.pem", "w") as o:
              o.write(privKeyPEM.decode('ascii'))
          
          encryptor = PKCS1_OAEP.new(pubKey)
          encrypted = encryptor.encrypt(msg)
          with open("Encrypted message.txt", "w") as o:
              o.write(str(binascii.hexlify(encrypted)))
          
          decryptor = PKCS1_OAEP.new(keyPair)
          decrypted = decryptor.decrypt(encrypted)
          with open("Decrypted message.txt", "w") as o:
              o.write(str(decrypted))
          
              #outmsg.set(url_bytes)
        def rsa_decrypt(user_text):
          msg = ""
          msg = user_text
          message = msg
        def con():
          user_text = (user_input_text.get())
          text1 = user_text
          text1 = str(text1)
          choice = user_choice.get()
          
          if choice == 0:
            rsa_encrypt(text1)
          else:
            rsa_decrypt(text1)
              #gui items
    
        ttk.Radiobutton(win, text="Encrypt", variable=user_choice, value=0, bootstyle=INFO).place(
            relx=0.75, rely=0.4, anchor=CENTER)
        ttk.Radiobutton(win, text="Decrypt", variable=user_choice, value=1, bootstyle=INFO).place(
            relx=0.9, rely=0.4, anchor=CENTER)
        
        msg1 = ttk.Label(win, text='Type your string to Encrypt/Decrypt', bootstyle=INFO)
        msg1.place(relx=0.5, rely=0.05, anchor=CENTER)
        msg2 = ttk.Label(win, text='Kindly check the new RSA files which are created in your current working directory', bootstyle=WARNING)
        msg2.place(relx=0.5, rely=0.65, anchor=CENTER)
        user_input_text = Entry(win)
        user_input_text.place(relx=0.5, rely=0.15, anchor=CENTER, width=500, height=50)
        user_input_text.focus_set()
        stop = ttk.Button(win, text='Exit', width=10, command=win.destroy, bootstyle="DANGER-OUTLINE")
        stop.place(relx=0.10, rely=1, anchor=SE)
        
        
        out = Entry(win, text=outmsg).place(
            relx=0.5, rely=0.75, anchor=CENTER,  width=500, height=50)
        
        convert = ttk.Button(win, text='Convert', width=20, command=con, bootstyle="WARNING-OUTLINE")
        convert.place(relx=0.5, rely=0.4, anchor=CENTER)     
sel.trace('w',my_upd) # on change of string variable 
win.config(menu=menubar)
win.mainloop()  # Keep the window open