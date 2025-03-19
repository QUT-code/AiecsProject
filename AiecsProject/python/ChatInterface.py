import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import socket
import threading
from datetime import datetime
import os
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Server configuration
HOST = '3.107.181.28'  # Replace with your server's public IP
PORT = 12345

# AES encryption key (must be 16, 24, or 32 bytes long)
KEY = b'mysecretkey12345'  # Replace with a secure key

# Get the username from command-line arguments
username = sys.argv[1] if len(sys.argv) > 1 else "Unknown"

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Function to encrypt data using AES
def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data.encode(), AES.block_size))

# Function to decrypt data using AES
def decrypt_data(encrypted_data):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()

# Function to send messages
def send_message():
    message = entry_message.get()
    if message:
        try:
            # Encrypt the message
            encrypted_message = encrypt_data(message)
            # Send the encrypted message
            client_socket.send(f"text:{username}:{base64.b64encode(encrypted_message).decode()}".encode())
            timestamp = datetime.now().strftime("%H:%M")
            display_message(f"You: {message}", timestamp, "user")
            entry_message.delete(0, tk.END)
        except Exception as e:
            print(f"Error sending message: {e}")

# Function to send files (images, documents, etc.)
def send_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file:
            file_data = file.read()
        # Encrypt the file data
        encrypted_file_data = encrypt_data(base64.b64encode(file_data).decode())
        try:
            # Send the encrypted file
            client_socket.send(f"file:{username}:{file_name}:{base64.b64encode(encrypted_file_data).decode()}".encode())
            timestamp = datetime.now().strftime("%H:%M")
            if file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                # Display image in the chat window
                display_image(file_data, f"You sent an image:", timestamp, "user")
            else:
                # Display file name for non-image files
                display_message(f"You sent a file: {file_name}", timestamp, "user")
        except Exception as e:
            print(f"Error sending file: {e}")

# Function to display messages in bubbles
def display_message(message, timestamp, sender):
    frame = tk.Frame(chat_window, bg="white")
    frame.pack(anchor="e" if sender == "user" else "w", pady=5)

    # Message bubble
    bubble = tk.Label(
        frame,
        text=message,
        bg="#DCF8C6" if sender == "user" else "#ECECEC",
        fg="black",
        font=("Arial", 12),
        padx=10,
        pady=5,
        wraplength=300,
        justify="left",
        bd=0,
        relief="flat",
    )
    bubble.pack()

    # Timestamp
    timestamp_label = tk.Label(
        frame,
        text=timestamp,
        bg="white",
        fg="gray",
        font=("Arial", 8),
    )
    timestamp_label.pack()

# Function to display images in the chat window
def display_image(image_data, prefix, timestamp, sender):
    try:
        # Convert image data to a PhotoImage object
        image = Image.open(image_data)
        image = image.resize((200, 200), Image.ANTIALIAS)  # Resize image for display
        photo = ImageTk.PhotoImage(image)

        # Display the image in a bubble
        frame = tk.Frame(chat_window, bg="white")
        frame.pack(anchor="e" if sender == "user" else "w", pady=5)

        # Image bubble
        bubble = tk.Label(
            frame,
            image=photo,
            bg="#DCF8C6" if sender == "user" else "#ECECEC",
            bd=0,
            relief="flat",
        )
        bubble.image = photo  # Keep a reference to avoid garbage collection
        bubble.pack()

        # Timestamp
        timestamp_label = tk.Label(
            frame,
            text=timestamp,
            bg="white",
            fg="gray",
            font=("Arial", 8),
        )
        timestamp_label.pack()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to display image: {e}")

# Function to handle Enter key press
def on_enter_key(event):
    send_message()

# Function to receive messages
def receive_messages():
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if data:
                if data.startswith("file:"):
                    # Handle received file (image or other files)
                    sender, file_name, encrypted_file_data_base64 = data.split(":", 2)
                    encrypted_file_data = base64.b64decode(encrypted_file_data_base64)
                    # Decrypt the file data
                    file_data = base64.b64decode(decrypt_data(encrypted_file_data))
                    timestamp = datetime.now().strftime("%H:%M")
                    if file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        # Display received image
                        display_image(file_data, f"{sender} sent an image:", timestamp, "received")
                    else:
                        # Display received file name
                        display_message(f"{sender} sent a file: {file_name}", timestamp, "received")
                else:
                    # Handle text message
                    sender, encrypted_message_base64 = data.split(":", 1)
                    encrypted_message = base64.b64decode(encrypted_message_base64)
                    # Decrypt the message
                    message = decrypt_data(encrypted_message)
                    timestamp = datetime.now().strftime("%H:%M")
                    display_message(f"{sender}: {message}", timestamp, "received")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# GUI Setup
root = tk.Tk()
root.title("Chat Interface")
root.resizable(False, False)  # Prevent resizing
root.configure(bg="white")

# Chat Window
chat_window = tk.Canvas(root, bg="white")
chat_window.pack(fill=tk.BOTH, expand=True)

# Scrollbar
scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL, command=chat_window.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_window.configure(yscrollcommand=scrollbar.set)

# Message Entry Frame
entry_frame = tk.Frame(root, bg="white")
entry_frame.pack(fill=tk.X, pady=10)

# Message Entry
entry_message = tk.Entry(entry_frame, width=50, font=("Arial", 12))
entry_message.pack(side=tk.LEFT, padx=10)
entry_message.bind("<Return>", on_enter_key)  # Bind Enter key to send_message

# Send Text Button
button_send_text = tk.Button(entry_frame, text="Send", command=send_message, width=10, font=("Arial", 12))
button_send_text.pack(side=tk.LEFT)

# Attachment Button
button_attachment = tk.Button(entry_frame, text="Send File", command=send_file, width=10, font=("Arial", 12))
button_attachment.pack(side=tk.LEFT, padx=10)

# Start a thread to receive messages
threading.Thread(target=receive_messages, daemon=True).start()

root.mainloop()