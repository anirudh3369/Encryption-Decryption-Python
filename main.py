import tkinter as tk
from tkinter import messagebox
import mysql.connector

MORSE_CODE_DICT = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/'}


def save_to_database(tool, input_text, output_text):
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="1234",
            database="mydb"
        )

        cursor = connection.cursor()
        query = "INSERT INTO encryption_data (tool, input_text, output_text) VALUES (%s, %s, %s)"
        data = (tool, input_text, output_text)
        cursor.execute(query, data)

        connection.commit()
        messagebox.showinfo("Success", "Data saved to the database.")
    except Exception as e:
        messagebox.showerror("Error", f"Error saving data to the database: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
def text_to_morse(text):
    text = text.upper()
    morse_code = [MORSE_CODE_DICT[char] if char in MORSE_CODE_DICT else char for char in text]
    return ' '.join(morse_code)

def morse_to_text(morse_code):
    inverted_dict = {v: k for k, v in MORSE_CODE_DICT.items()}
    text = [inverted_dict[code] if code in inverted_dict else code for code in morse_code.split(' ')]
    return ''.join(text)

def caesar_cipher(text, shift):
    result = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                shifted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                shifted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            shifted_char = char

        result += shifted_char

    return result

def vigenere_encrypt(plain_text, key):
    encrypted_text, key = "", key.upper()
    for i, char in enumerate(plain_text):
        if char.isalpha():
            key_index, key_char = i % len(key), key[i % len(key)]
            shift, ord_base = ord(key_char), ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - ord_base + shift - ord('A')) % 26 + ord_base)
        else:
            encrypted_char = char
        encrypted_text += encrypted_char
    return encrypted_text

def vigenere_decrypt(encrypted_text, key):
    decrypted_text, key = "", key.upper()
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            key_index, key_char = i % len(key), key[i % len(key)]
            shift, ord_base = ord(key_char), ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - ord_base - shift + ord('A')) % 26 + ord_base)
        else:
            decrypted_char = char
        decrypted_text += decrypted_char
    return decrypted_text

def atbash_cipher(text):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr(219 - ord(char))
            else:
                result += chr(155 - ord(char))
        else:
            result += char
    return result

def create_polybus_square():
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    square = [[0] * 5 for _ in range(5)]
    index = 0

    for i in range(5):
        for j in range(5):
            square[i][j] = alphabet[index]
            index += 1

    return square

def encode_polybus_square(square, plaintext):
    encoded_text = ""

    for char in plaintext:
        if char == "j":
            char = "i"
        for i in range(5):
            for j in range(5):
                if square[i][j] == char:
                    encoded_text += f"{i+1}{j+1}"
                    break

    return encoded_text

def decode_polybus_square(square, encoded_text):
    decoded_text = ""
    index = 0

    while index < len(encoded_text):
        row = int(encoded_text[index]) - 1
        col = int(encoded_text[index + 1]) - 1
        decoded_text += square[row][col]
        index += 2

    return decoded_text

def text_to_ascii(text):
    ascii_art = ""
    for char in text:
        ascii_code = ord(char)
        ascii_art += str(ascii_code) + " "
    return ascii_art

def ascii_to_text(ascii_art):
    ascii_codes = ascii_art.split()
    text = ""
    for code in ascii_codes:
        try:
            char = chr(int(code))
            text += char
        except ValueError:
            pass
    return text

def rail_fence_encrypt(plain_text, rails):
    fence = [['\n' for _ in range(len(plain_text))]
             for _ in range(rails)]

    direction = -1
    row = 0
    col = 0

    for char in plain_text:
        if row == 0 or row == rails - 1:
            direction *= -1

        fence[row][col] = char
        col += 1

        if direction == -1:
            row -= 1
        else:
            row += 1

    encrypted_text = ''
    for i in range(rails):
        for j in range(len(plain_text)):
            if fence[i][j] != '\n':
                encrypted_text += fence[i][j]

    return encrypted_text


def rail_fence_decrypt(encrypted_text, rails):
    fence = [['\n' for _ in range(len(encrypted_text))]
             for _ in range(rails)]

    direction = -1
    row = 0

    for i in range(len(encrypted_text)):
        fence[row][i] = '*'

        if row == 0 or row == rails - 1:
            direction *= -1

        if direction == -1:
            row -= 1
        else:
            row += 1

    index = 0
    for i in range(rails):
        for j in range(len(encrypted_text)):
            if fence[i][j] == '*' and index < len(encrypted_text):
                fence[i][j] = encrypted_text[index]
                index += 1

    decrypted_text = ''
    row = 0
    col = 0
    for _ in range(len(encrypted_text)):
        if row == 0 or row == rails - 1:
            direction *= -1

        decrypted_text += fence[row][col]
        col += 1

        if direction == -1:
            row -= 1
        else:
            row += 1

    return decrypted_text

def morse_gui():
    def encode():
        text = input_text.get("1.0", "end-1c")
        encoded_text = text_to_morse(text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encoded_text)
        save_to_database("Morse Code", text, encoded_text)

    def decode():
        morse_code = input_text.get("1.0", "end-1c")
        decoded_text = morse_to_text(morse_code)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decoded_text)
        save_to_database("Morse Code", morse_code, decoded_text)

    morse_window = tk.Toplevel(root)
    morse_window.title("Morse Code Encryption")

    input_label = tk.Label(morse_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(morse_window, height=5, width=30)
    input_text.pack()

    encode_button = tk.Button(morse_window, text="Encode", command=encode)
    encode_button.pack()

    decode_button = tk.Button(morse_window, text="Decode", command=decode)
    decode_button.pack()

    output_label = tk.Label(morse_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(morse_window, height=5, width=30)
    output_text.pack()

def caesar_gui():
    def encrypt_decrypt():
        text = input_text.get("1.0", "end-1c")
        shift = int(key_entry.get())
        encrypted_text = caesar_cipher(text, shift)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        save_to_database("Caesar Cipher", text, encrypted_text)

    caesar_window = tk.Toplevel(root)
    caesar_window.title("Caesar Cipher")

    input_label = tk.Label(caesar_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(caesar_window, height=5, width=30)
    input_text.pack()

    key_label = tk.Label(caesar_window, text="Shift Key:")
    key_label.pack()

    key_entry = tk.Entry(caesar_window)
    key_entry.pack()

    encrypt_decrypt_button = tk.Button(caesar_window, text="Encrypt/Decrypt", command=encrypt_decrypt)
    encrypt_decrypt_button.pack()

    output_label = tk.Label(caesar_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(caesar_window, height=5, width=30)
    output_text.pack()

def vigenere_gui():
    def encrypt_decrypt():
        text = input_text.get("1.0", "end-1c")
        key = key_entry.get()
        encrypted_text = vigenere_encrypt(text, key)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        save_to_database("Vigenere Cipher", text, encrypted_text)

    vigenere_window = tk.Toplevel(root)
    vigenere_window.title("Vigenère Cipher")

    input_label = tk.Label(vigenere_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(vigenere_window, height=5, width=30)
    input_text.pack()

    key_label = tk.Label(vigenere_window, text="Key:")
    key_label.pack()

    key_entry = tk.Entry(vigenere_window)
    key_entry.pack()

    encrypt_decrypt_button = tk.Button(vigenere_window, text="Encrypt/Decrypt", command=encrypt_decrypt)
    encrypt_decrypt_button.pack()

    output_label = tk.Label(vigenere_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(vigenere_window, height=5, width=30)
    output_text.pack()

def atbash_gui():
    def encrypt_decrypt():
        text = input_text.get("1.0", "end-1c")
        encrypted_text = atbash_cipher(text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        save_to_database("Atbash Cipher", text, encrypted_text)

    atbash_window = tk.Toplevel(root)
    atbash_window.title("Atbash Cipher")

    input_label = tk.Label(atbash_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(atbash_window, height=5, width=30)
    input_text.pack()

    encrypt_decrypt_button = tk.Button(atbash_window, text="Encrypt/Decrypt", command=encrypt_decrypt)
    encrypt_decrypt_button.pack()

    output_label = tk.Label(atbash_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(atbash_window, height=5, width=30)
    output_text.pack()

def polybus_gui():
    def encode():
        plaintext = input_text.get("1.0", "end-1c")
        encoded_text = encode_polybus_square(create_polybus_square(), plaintext)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encoded_text)
        save_to_database("Polybus Square Cipher", plaintext, encoded_text)

    def decode():
        encoded_text = input_text.get("1.0", "end-1c")
        decoded_text = decode_polybus_square(create_polybus_square(), encoded_text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decoded_text)
        save_to_database("Polybus Square Cipher", encoded_text, decoded_text)

    polybus_window = tk.Toplevel(root)
    polybus_window.title("Polybus Square Cipher")

    input_label = tk.Label(polybus_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(polybus_window, height=5, width=30)
    input_text.pack()

    encode_button = tk.Button(polybus_window, text="Encode", command=encode)
    encode_button.pack()

    decode_button = tk.Button(polybus_window, text="Decode", command=decode)
    decode_button.pack()

    output_label = tk.Label(polybus_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(polybus_window, height=5, width=30)
    output_text.pack()
def ascii_gui():
    def text_to_ascii_action():
        text = input_text.get("1.0", "end-1c")
        ascii_art = text_to_ascii(text)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", ascii_art)
        save_to_database("ASCII Translation", text, ascii_art)

    def ascii_to_text_action():
        ascii_art = input_text.get("1.0", "end-1c")
        text = ascii_to_text(ascii_art)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", text)
        save_to_database("ASCII Translation", ascii_art, text)

    ascii_window = tk.Toplevel(root)
    ascii_window.title("ASCII Translation")

    input_label = tk.Label(ascii_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(ascii_window, height=5, width=30)
    input_text.pack()

    text_to_ascii_button = tk.Button(ascii_window, text="Text to ASCII", command=text_to_ascii_action)
    text_to_ascii_button.pack()

    ascii_to_text_button = tk.Button(ascii_window, text="ASCII to Text", command=ascii_to_text_action)
    ascii_to_text_button.pack()

    output_label = tk.Label(ascii_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(ascii_window, height=5, width=30)
    output_text.pack()

def rail_fence_gui():
    def encrypt():
        text = input_text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        encrypted_text = rail_fence_encrypt(text, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", encrypted_text)
        save_to_database("Rail Fence Cipher", text, encrypted_text)

    def decrypt():
        text = input_text.get("1.0", "end-1c")
        rails = int(rails_entry.get())
        decrypted_text = rail_fence_decrypt(text, rails)
        output_text.delete("1.0", "end")
        output_text.insert("1.0", decrypted_text)
        save_to_database("Rail Fence Cipher", text, decrypted_text)

    rail_fence_window = tk.Toplevel(root)
    rail_fence_window.title("Rail Fence Cipher")

    input_label = tk.Label(rail_fence_window, text="Input:")
    input_label.pack()

    input_text = tk.Text(rail_fence_window, height=5, width=30)
    input_text.pack()

    rails_label = tk.Label(rail_fence_window, text="Number of Rails:")
    rails_label.pack()

    rails_entry = tk.Entry(rail_fence_window)
    rails_entry.pack()

    encrypt_button = tk.Button(rail_fence_window, text="Encrypt", command=encrypt)
    encrypt_button.pack()

    decrypt_button = tk.Button(rail_fence_window, text="Decrypt", command=decrypt)
    decrypt_button.pack()

    output_label = tk.Label(rail_fence_window, text="Output:")
    output_label.pack()

    output_text = tk.Text(rail_fence_window, height=5, width=30)
    output_text.pack()

root = tk.Tk()
root.title("Encryption Tools")

morse_button = tk.Button(root, text="Morse Code", command=morse_gui)
morse_button.pack()

caesar_button = tk.Button(root, text="Caesar Cipher", command=caesar_gui)
caesar_button.pack()


vigenere_button = tk.Button(root, text="Vigenère Cipher", command=vigenere_gui)
vigenere_button.pack()

atbash_button = tk.Button(root, text="Atbash Cipher", command=atbash_gui)
atbash_button.pack()

polybus_button = tk.Button(root, text="Polybus Square Cipher", command=polybus_gui)
polybus_button.pack()

ascii_button = tk.Button(root, text="ASCII Translation", command=ascii_gui)
ascii_button.pack()

rail_fence_button = tk.Button(root, text="Rail Fence Cipher", command=rail_fence_gui)
rail_fence_button.pack()

# Create buttons and functions for other encryption tools here

quit_button = tk.Button(root, text="Quit", command=root.quit)
quit_button.pack()

root.mainloop()
