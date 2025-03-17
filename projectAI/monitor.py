import tkinter as tk
from tkinter import scrolledtext
from messages import send_message
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hmac

# Secret key for encryption (AES) and message integrity (HMAC)
AES_SECRET_KEY = get_random_bytes(16)  # AES key (128-bit)
HMAC_SECRET_KEY = get_random_bytes(32)  # HMAC key

# Function to encrypt a message using AES (Confidentiality)
def encrypt_message(message: str) -> str:
    cipher = AES.new(AES_SECRET_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    nonce = cipher.nonce
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

# Function to decrypt a message using AES (Confidentiality)
def decrypt_message(encrypted_message: str) -> str:
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(AES_SECRET_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Function to compute HMAC (Message Integrity)
def compute_hmac(message: str) -> str:
    return hmac.new(HMAC_SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()

# Function to verify the HMAC of a message (Message Integrity)
def verify_hmac(message: str, hmac_to_verify: str) -> bool:
    computed_hmac = compute_hmac(message)
    return hmac.compare_digest(computed_hmac, hmac_to_verify)

def run_gui():
    # Create a new window for Sender1
    sender1_window = tk.Tk()
    sender1_window.title("Sender1 - Phone")
    sender1_window.resizable(False, False)  # Prevent resizing

    # Sender1 Chat Window (scrollable)
    sender1_chat_window = scrolledtext.ScrolledText(sender1_window, wrap=tk.WORD, width=50, height=15, state=tk.DISABLED)
    sender1_chat_window.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

    # Entry field for Sender1's message
    sender1_entry = tk.Entry(sender1_window, width=40)
    sender1_entry.grid(row=1, column=0, padx=10, pady=10)

    # Send Button for Sender1 (simplified)
    send_button_sender1 = tk.Button(sender1_window, text="Send", command=lambda: send_message_sender1(sender1_entry, sender1_chat_window, sender2_chat_window, "Sender1", "left"))
    send_button_sender1.grid(row=1, column=1, padx=10, pady=10)

    # Function to send message when pressing Enter key for Sender1
    def on_enter_sender1(event):
        send_message_sender1(sender1_entry, sender1_chat_window, sender2_chat_window, "Sender1", "left")

    sender1_entry.bind('<Return>', on_enter_sender1)  # Bind Enter key to send message

    # Create a new window for Sender2
    sender2_window = tk.Tk()
    sender2_window.title("Sender2 - Phone")
    sender2_window.resizable(False, False)  # Prevent resizing

    # Sender2 Chat Window (scrollable)
    sender2_chat_window = scrolledtext.ScrolledText(sender2_window, wrap=tk.WORD, width=50, height=15, state=tk.DISABLED)
    sender2_chat_window.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

    # Entry field for Sender2's message
    sender2_entry = tk.Entry(sender2_window, width=40)
    sender2_entry.grid(row=1, column=0, padx=10, pady=10)

    # Send Button for Sender2 (simplified)
    send_button_sender2 = tk.Button(sender2_window, text="Send", command=lambda: send_message_sender2(sender2_entry, sender2_chat_window, sender1_chat_window, "Sender2", "right"))
    send_button_sender2.grid(row=1, column=1, padx=10, pady=10)

    # Function to send message when pressing Enter key for Sender2
    def on_enter_sender2(event):
        send_message_sender2(sender2_entry, sender2_chat_window, sender1_chat_window, "Sender2", "right")

    sender2_entry.bind('<Return>', on_enter_sender2)  # Bind Enter key to send message

    # Create Admin Panel for monitoring messages
    admin_window = tk.Tk()
    admin_window.title("Admin Panel - Message Monitoring")
    admin_window.resizable(False, False)  # Prevent resizing

    # Admin Chat Window (scrollable)
    admin_chat_window = scrolledtext.ScrolledText(admin_window, wrap=tk.WORD, width=50, height=15, state=tk.DISABLED)
    admin_chat_window.grid(row=0, column=0, padx=10, pady=10, columnspan=2)

    # Display original, encrypted message, and HMAC status
    def monitor_message(message):
        encrypted_message = encrypt_message(message)
        message_hmac = compute_hmac(message)

        admin_chat_window.config(state=tk.NORMAL)
        admin_chat_window.insert(tk.END, f"Original Message: {message}\n")
        admin_chat_window.insert(tk.END, f"Encrypted Message: {encrypted_message}\n")
        admin_chat_window.insert(tk.END, f"HMAC of Message: {message_hmac}\n")
        admin_chat_window.insert(tk.END, "---------------------------------------\n")
        admin_chat_window.config(state=tk.DISABLED)

    # Trigger message monitoring when Sender1 sends a message
    def send_message_sender1(entry, sender1_chat_window, sender2_chat_window, sender, position):
        message = entry.get()
        if message:
            # Display the message in Sender1 chat
            sender1_chat_window.config(state=tk.NORMAL)
            sender1_chat_window.insert(tk.END, f"{sender}: {message}\n")
            sender1_chat_window.config(state=tk.DISABLED)
            entry.delete(0, tk.END)

            # Monitor and log the message in Admin Panel
            monitor_message(message)

            # Send to Sender2 window (simulating real-time chat)
            sender2_chat_window.config(state=tk.NORMAL)
            sender2_chat_window.insert(tk.END, f"{sender}: {message}\n")
            sender2_chat_window.config(state=tk.DISABLED)

    # Trigger message monitoring when Sender2 sends a message
    def send_message_sender2(entry, sender2_chat_window, sender1_chat_window, sender, position):
        message = entry.get()
        if message:
            # Display the message in Sender2 chat
            sender2_chat_window.config(state=tk.NORMAL)
            sender2_chat_window.insert(tk.END, f"{sender}: {message}\n")
            sender2_chat_window.config(state=tk.DISABLED)
            entry.delete(0, tk.END)

            # Monitor and log the message in Admin Panel
            monitor_message(message)

            # Send to Sender1 window (simulating real-time chat)
            sender1_chat_window.config(state=tk.NORMAL)
            sender1_chat_window.insert(tk.END, f"{sender}: {message}\n")
            sender1_chat_window.config(state=tk.DISABLED)

    # Update the send functions to include the monitoring logic
    send_button_sender1.config(command=lambda: send_message_sender1(sender1_entry, sender1_chat_window, sender2_chat_window, "Sender1", "left"))
    send_button_sender2.config(command=lambda: send_message_sender2(sender2_entry, sender2_chat_window, sender1_chat_window, "Sender2", "right"))

    # Start both GUI windows
    sender1_window.after(1000, lambda: sender2_window.deiconify())  # Display sender2 window after sender1 window
    sender1_window.after(1000, lambda: admin_window.deiconify())  # Display admin window after sender1 window
    sender1_window.mainloop()
    sender2_window.mainloop()
    admin_window.mainloop()

