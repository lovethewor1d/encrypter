# Encrypter - A Python Encryption Tool

## Overview

This is a Python-based encryption tool built using Tkinter for the GUI and several popular encryption methods. The tool allows users to easily encode and decode data using various encryption techniques, including:

- Caesar Cipher
- XOR Encryption
- Rot13
- Base64
- HTML Encoding
- URL Encoding
- RSA Encryption

The program is designed to be user-friendly, with a simple interface to select encryption options and input text. It is great for both beginners learning about encryption and those looking for a simple tool for encoding and decoding data.

## Features

- **Caesar Cipher:** A simple shift cipher where each letter in the plaintext is shifted by a certain number of positions down or up the alphabet.
- **XOR Encryption:** A symmetric key algorithm that uses a key for both encryption and decryption.
- **Rot13:** A letter substitution cipher that shifts each letter by 13 positions in the alphabet.
- **Base64 Encoding/Decoding:** Encodes and decodes data into a base64 format.
- **HTML Encoding/Decoding:** Encodes and decodes text for safe HTML display.
- **URL Encoding/Decoding:** Encodes and decodes special characters in URLs.
- **RSA Encryption/Decryption:** Asymmetric encryption that uses a pair of keys, public and private, for encryption and decryption.

## Requirements

To run the Encrypter tool, you need the following libraries:

- `tkinter`
- `ttkbootstrap`
- `pycryptodome`

These can be installed using `pip`:

```bash
pip install ttkbootstrap pycryptodome
```

## How to Use

1. **Launch the program**: Run the `encrypter.py` script.
2. **Select an encryption method**: From the dropdown, choose one of the following encryption methods: 
    - Caesar Cipher
    - XOR Encryption
    - Rot13
    - Base64 Encoding
    - HTML Encoding
    - URL Encoding
    - RSA Encryption
3. **Enter the text**: In the input box, enter the text you want to encrypt or decrypt.
4. **Select the action**: Depending on the method, select whether to "Encrypt" or "Decrypt" the input.
5. **Get the result**: The output will be shown below the input box, where you can see the result of the encryption or decryption process.

## Menu Options

- **Help**: Displays information about each encryption method.
- **Exit**: Closes the program.

## How to Contribute

Feel free to fork the repository, submit pull requests, or report issues. Contributions are welcome!

## Acknowledgements

- Tkinter and ttkbootstrap for the graphical user interface.
- PyCryptodome for the cryptographic functions.
- Thanks to open-source contributors for their work in encryption algorithms.
```
