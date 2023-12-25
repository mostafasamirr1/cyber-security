import streamlit as st
from PIL import Image
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad

# Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    result = ""
    key_length = len(key)

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            result += chr((ord(char.upper()) + shift - ord('A')) % 26 + ord('A'))
        else:
            result += char

    return result

def vigenere_decrypt(ciphertext, key):
    result = ""
    key_length = len(key)

    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            result += chr((ord(char.upper()) - shift - ord('A')) % 26 + ord('A'))
        else:
            result += char

    return result

# Blowfish Cipher
def blowfish_encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def blowfish_decrypt(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_text = cipher.decrypt(ciphertext)
    return unpad(decrypted_text, Blowfish.block_size).decode()

def main():
    st.title("Encryption/Decryption App")
    

cipher_choices = [
        "Vigenere Cipher",
        "Blowfish"
    ]

selected_cipher = st.selectbox("Choose a cipher:", cipher_choices)

st.sidebar.header("Key and Text Input")

key = st.sidebar.text_input("Enter Key:")
plaintext = st.sidebar.text_area("Enter Text:", height=10)

process_button = st.sidebar.button("Encrypt/Decrypt")

if process_button:
        if selected_cipher == "Vigenere Cipher":
            encrypted_text = vigenere_encrypt(plaintext, key)
            decrypted_text = vigenere_decrypt(encrypted_text, key)
        elif selected_cipher == "Blowfish":
            key = pad(key.encode(), Blowfish.block_size)
            encrypted_text = blowfish_encrypt(plaintext, key)
            decrypted_text = blowfish_decrypt(encrypted_text, key)
        else:
            encrypted_text = decrypted_text = "Select a cipher to perform encryption and decryption."

        st.header("Results")

        st.subheader("Encrypted Text:")
        st.text(encrypted_text)

        st.subheader("Decrypted Text:")
        st.text(decrypted_text)

if __name__ == "__main__":
    main()
